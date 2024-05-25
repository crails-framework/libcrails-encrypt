#include "digest.hpp"

using namespace std;
using namespace Crails;

string Digest::to_string() const
{
  string output;

  output.resize(md_len * 2);
  for (unsigned int i = 0 ; i < md_len ; ++i)
    std::sprintf(&output[i * 2], "%02x", md_value[i]);
  return output;
}

string Digest::to_base64() const
{
  char buffer[EVP_MAX_MD_SIZE];

  EVP_EncodeBlock(reinterpret_cast<unsigned char*>(buffer), md_value, md_len);
  return string(buffer);
}
