#include "argon2id.hpp"
#include "secure_compare.hpp"
#include "ssl_base64.hpp"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <vector>

using namespace std;
using namespace Crails;

static constexpr size_t hash_size = 32;
static constexpr size_t salt_size = 16;

static string random_salt()
{
  string salt(salt_size, '\0');

  if (RAND_bytes(reinterpret_cast<unsigned char*>(salt.data()), salt.size()) != 1)
    throw runtime_error("no secure random source");
  return salt;
}

Argon2idDigest::Argon2idDigest(const string_view password, const Argon2idParameters& parameters)
  : Argon2idDigest(password, random_salt(), parameters)
{
}

Argon2idDigest::Argon2idDigest(const string_view password, const string_view salt, const Argon2idParameters& parameters)
  : parameters(parameters), salt(salt)
{
  unique_ptr<EVP_KDF, decltype(&EVP_KDF_free)> kdf(EVP_KDF_fetch(nullptr, "ARGON2ID", nullptr), EVP_KDF_free);

  if (!kdf)
    throw runtime_error("Argon2id is not available (requires OpenSSL 3.2 or later)");

  unique_ptr<EVP_KDF_CTX, decltype(&EVP_KDF_CTX_free)> context(EVP_KDF_CTX_new(kdf.get()), EVP_KDF_CTX_free);
  uint32_t iterations = parameters.iterations, memory = parameters.memory_kib, lanes = parameters.parallelism;
  OSSL_PARAM params[] = { // parameter names as documented in EVP_KDF-ARGON2(7)
    OSSL_PARAM_construct_octet_string("pass", const_cast<char*>(password.data()), password.size()),
    OSSL_PARAM_construct_octet_string("salt", const_cast<char*>(salt.data()), salt.size()),
    OSSL_PARAM_construct_uint32("iter", &iterations),
    OSSL_PARAM_construct_uint32("memcost", &memory),
    OSSL_PARAM_construct_uint32("lanes", &lanes),
    OSSL_PARAM_construct_end()
  };

  md_len = hash_size;
  if (EVP_KDF_derive(context.get(), md_value, md_len, params) != 1)
    throw runtime_error("Argon2id failed (invalid parameters or salt shorter than 8 bytes?)");
}

string Argon2idDigest::password_hash() const
{
  return "$argon2id$v=19$m=" + std::to_string(parameters.memory_kib)
       + ",t=" + std::to_string(parameters.iterations)
       + ",p=" + std::to_string(parameters.parallelism)
       + '$' + ssl_base64_encode(salt, false)
       + '$' + ssl_base64_encode(string_view(reinterpret_cast<const char*>(md_value), md_len), false);
}

bool Argon2idDigest::verify(const string_view password, const string_view stored)
{
  // "$argon2id$v=19$m=..,t=..,p=..$salt$hash" splits into 6 fields, the first being empty
  vector<string_view> fields;

  for (size_t begin = 0, end = 0 ; end != string_view::npos ; begin = end + 1)
  {
    end = stored.find('$', begin);
    fields.push_back(stored.substr(begin, end == string_view::npos ? end : end - begin));
  }
  if (fields.size() != 6 || !fields[0].empty() || fields[1] != "argon2id" || fields[2] != "v=19")
    return false;

  Argon2idParameters parameters;
  string parameter_field(fields[3]);
  int consumed = 0;

  if (sscanf(parameter_field.c_str(), "m=%u,t=%u,p=%u%n",
             &parameters.memory_kib, &parameters.iterations, &parameters.parallelism, &consumed) != 3
   || static_cast<size_t>(consumed) != parameter_field.size())
    return false;

  string salt, expected;

  try
  {
    salt = ssl_base64_decode(fields[4]);
    expected = ssl_base64_decode(fields[5]);
  }
  catch (const runtime_error&) { return false; }
  if (expected.size() != hash_size)
    return false;

  const Argon2idDigest candidate(password, salt, parameters);

  return secure_compare(string_view(reinterpret_cast<const char*>(candidate.md_value), hash_size), expected);
}
