#include "md5.hpp"
#include <openssl/evp.h>

using namespace std;

namespace Crails
{
  string md5(const string& content)
  {
    Md5Digest digest;

    digest << content;
    return digest.to_string();
  }
}
