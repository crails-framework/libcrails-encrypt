#include "pbkdf2_hmac.hpp"
#include <crails/utils/base64.hpp>
#include <sstream>
#include <cctype>
#include <algorithm>

using namespace std;
using namespace Crails;

Pbkdf2HmacDigest::Pbkdf2HmacDigest(const string_view password, const string_view salt, const EVP_MD* digest)
  : iteration_count(4096), salt(salt), digest(digest)
{
  md_len = 64;
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

string Pbkdf2HmacDigest::password_hash() const
{
  stringstream hash;
  string md_name = EVP_MD_get0_name(digest);

  transform(md_name.begin(), md_name.end(), md_name.begin(), [](unsigned char c){ return tolower(c); });
  hash << "$pbkdf2-" << md_name
       << '$' << iteration_count
       << '$' << Crails::base64_encode(salt)
       << '$' << to_base64();
  return hash.str();
}
