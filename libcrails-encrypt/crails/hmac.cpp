#include "hmac.hpp"
#include <openssl/hmac.h>
#include <crails/utils/base64.hpp>

using namespace std;
using namespace Crails;
  
HmacDigest::HmacDigest(const EVP_MD* evp, const string& key, const string& message)
{
  ::HMAC(
    evp,
    key.c_str(), key.length(),
    reinterpret_cast<const unsigned char*>(message.c_str()), message.length(),
    md_value, &md_len
  );
}
