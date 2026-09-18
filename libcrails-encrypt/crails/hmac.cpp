#include "hmac.hpp"
#include <openssl/hmac.h>
#include <crails/utils/base64.hpp>
#include <stdexcept>

using namespace std;
using namespace Crails;

HmacDigest::HmacDigest(const string& strategy, const string& key, const string& message)
  : HmacDigest(Digest::find_by_name(strategy), key, message)
{
}

HmacDigest::HmacDigest(const EVP_MD* evp, const string& key, const string& message)
{
  ::HMAC(
    evp,
    key.c_str(), key.length(),
    reinterpret_cast<const unsigned char*>(message.c_str()), message.length(),
    md_value, &md_len
  );
}
