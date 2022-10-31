#include "message_digest.hpp"
#include <cstdio>
#include <stdexcept>

using namespace Crails;
using namespace std;

struct EvpEncodeContext
{
  EVP_CONTEXT_CTX* ptr;
  EvpEncodeContext() { ptr = EVP_ENCODE_CTX_new(); }
  ~EvpEncodeContext() { EVP_ENCODE_CTX_free(ptr); }
};

MessageDigest::MessageDigest(const EVP_MD* md) : context(EVP_MD_CTX_new()), md(md)
{
}

MessageDigest::MessageDigest(const std::string& strategy) : context(EVP_MD_CTX_new()), md(EVP_get_digestbyname(strategy.c_str()))
{
  if (!md)
    throw std::runtime_error("unknown digest routine `" + strategy + '`');
}

MessageDigest::~MessageDigest()
{
  EVP_MD_CTX_free(context);
}

MessageDigest& MessageDigest::operator<<(const string& input)
{
  if (!initialized) initialize();
  EVP_DigestUpdate(context, input.c_str(), input.length());
  return *this;
}

MessageDigest& MessageDigest::operator>>(string& output)
{
  output = to_string();
  return *this;
}

string MessageDigest::to_string()
{
  string output;

  if (initialized) finalize();
  output.resize(md_len * 2);
  for (unsigned int i = 0 ; i < md_len ; ++i)
    std::sprintf(&output[i * 2], "%02x", md_value[i]);
  return output;
}

string MessageDigest::to_base64()
{
  EvpEncodeContext context;
  char buffer[EVP_MAX_MD_SIZE];
  int output_length;

  if (initialized) finalize();
  EVP_EncodeInit(context.ptr);
  EVP_EncodeBlock(reinterpret_cast<unsigned char*>(buffer), md_value, md_len);
  EVP_EncodeFinal(context.ptr, reinterpret_cast<unsigned char*>(buffer), &output_length);
  return string(buffer);
}

void MessageDigest::initialize()
{
  EVP_DigestInit_ex2(context, md, NULL);
  initialized = true;
}

void MessageDigest::finalize()
{
  EVP_DigestFinal_ex(context, md_value, &md_len);
  initialized = false;
}
