#include "digest.hpp"
#include <stdexcept>

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
  char buffer[EVP_MAX_MD_SIZE * 2];

  EVP_EncodeBlock(reinterpret_cast<unsigned char*>(buffer), md_value, md_len);
  return string(buffer);
}

const EVP_MD* Digest::find_by_name(const string& strategy)
{
  const EVP_MD* md = EVP_get_digestbyname(strategy.c_str());

  if (!md)
    throw runtime_error("unknown digest routine `" + strategy + '`');
  return md;
}
