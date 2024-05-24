#include "pbkdf2_hmac.hpp"

using namespace std;
using namespace Crails;

const unsigned int Pbkdf2HmacDigest::iteration_count = 4096;

Pbkdf2HmacDigest::Pbkdf2HmacDigest(const string_view password, const string_view salt, const EVP_MD* digest)
{
  md_len = 86;
  ::PKCS5_PBKDF2_HMAC(
    password.data(),
    password.length(),
    reinterpret_cast<const unsigned char*>(salt.data()),
    salt.length(),
    iteration_count,
    digest,
    md_len,
    md_value
  );
}
