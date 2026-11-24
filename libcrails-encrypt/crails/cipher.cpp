#include "cipher.hpp"
#include "ssl_base64.hpp"
#include <crails/utils/backtrace.hpp>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <fstream>
#include <memory>

using namespace std;
using namespace Crails;

constexpr unsigned char version = 1;
constexpr size_t key_size = 32, salt_size = 16, iv_size = 12, tag_size = 16;
constexpr size_t header_size = 1 + salt_size + iv_size;

using Context = unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

static inline void check(int result, const char* what)
{
  if (result != 1)
    throw boost_ext::runtime_error(string(what) + " failed");
}

struct Key
{
  unsigned char bytes[key_size];

  Key(const string& pass, const unsigned char* salt, unsigned int iterations)
  {
    if (pass.empty())
      throw boost_ext::runtime_error("Cipher: empty passphrase");
    check(PKCS5_PBKDF2_HMAC(pass.data(), pass.size(), salt, salt_size,
                            iterations, EVP_sha256(), key_size, bytes), "PBKDF2");
  }
  ~Key() { OPENSSL_cleanse(bytes, sizeof(bytes)); }
};

static string base64_encode(const string& in)
{
  string out(4 * ((in.size() + 2) / 3) + 1, '\0'); // + NUL written by OpenSSL

  EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()),
                  reinterpret_cast<const unsigned char*>(in.data()), in.size());
  out.pop_back();
  return out;
}

static string base64_decode(string in)
{
  while (!in.empty() && isspace(static_cast<unsigned char>(in.back())))
    in.pop_back();
  if (in.empty() || in.size() % 4 != 0)
    throw boost_ext::runtime_error("Cipher: invalid base64 input");

  string out(in.size() / 4 * 3, '\0');
  int length = EVP_DecodeBlock(reinterpret_cast<unsigned char*>(out.data()),
                               reinterpret_cast<const unsigned char*>(in.data()), in.size());
  if (length < 0)
    throw boost_ext::runtime_error("Cipher: invalid base64 input");
  for (size_t i = in.size() ; i > 0 && in[i - 1] == '=' ; --i)
    --length;
  out.resize(length);
  return out;
}

string Cipher::encrypt(const string& plaintext, const string& pass) const
{
  string out(header_size + plaintext.size() + tag_size, '\0');
  auto* header = reinterpret_cast<unsigned char*>(out.data());
  auto* body   = header + header_size;
  auto* tag    = body + plaintext.size();
  int   length = 0;

  header[0] = version;
  check(RAND_bytes(header + 1, salt_size + iv_size), "RAND_bytes");

  Key key(pass, header + 1, iterations);
  Context ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);

  check(EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, key.bytes, header + 1 + salt_size), "EVP_EncryptInit_ex");
  check(EVP_EncryptUpdate(ctx.get(), body, &length, reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size()), "EVP_EncryptUpdate");
  check(EVP_EncryptFinal_ex(ctx.get(), body + length, &length), "EVP_EncryptFinal_ex");
  check(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, tag_size, tag), "EVP_CTRL_AEAD_GET_TAG");
  return ssl_base64_encode(out);
}

string Cipher::decrypt(const string& mimetext, const string& pass) const
{
  const string raw = ssl_base64_decode(mimetext);

  if (raw.size() < header_size + tag_size || static_cast<unsigned char>(raw[0]) != version)
    throw boost_ext::runtime_error("Cipher: invalid ciphertext");

  const auto*  in        = reinterpret_cast<const unsigned char*>(raw.data());
  const size_t body_size = raw.size() - header_size - tag_size;
  string       plaintext(body_size, '\0');
  auto*        out       = reinterpret_cast<unsigned char*>(plaintext.data());
  int          length    = 0;

  Key key(pass, in + 1, iterations);
  Context ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);

  check(EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, key.bytes, in + 1 + salt_size), "EVP_DecryptInit_ex");
  check(EVP_DecryptUpdate(ctx.get(), out, &length, in + header_size, body_size), "EVP_DecryptUpdate");
  check(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, tag_size,
                            const_cast<unsigned char*>(in + header_size + body_size)), "EVP_CTRL_AEAD_SET_TAG");
  if (EVP_DecryptFinal_ex(ctx.get(), out + length, &length) != 1)
    throw boost_ext::runtime_error("Cipher: wrong passphrase or corrupted data");
  return plaintext;
}
