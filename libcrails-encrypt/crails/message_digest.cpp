#include "message_digest.hpp"
#include <cstdio>
#include <stdexcept>

using namespace Crails;
using namespace std;

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

MessageDigest& MessageDigest::operator<<(char input)
{
  if (!initialized) initialize();
  EVP_DigestUpdate(context, &input, 1);
  return *this;
}

MessageDigest& MessageDigest::operator>>(string& output)
{
  output = to_string();
  return *this;
}

string MessageDigest::to_string()
{
  if (initialized) finalize();
  return Digest::to_string();
}

string MessageDigest::to_base64()
{
  if (initialized) finalize();
  return Digest::to_base64();
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
