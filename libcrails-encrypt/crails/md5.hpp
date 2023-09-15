#ifndef  CRAILS_MD5_HPP
# define CRAILS_MD5_HPP

# include <string>
# include "message_digest.hpp"
# include "hmac.hpp"

namespace Crails
{
  struct Md5Digest : public MessageDigest
  {
    Md5Digest() : MessageDigest(EVP_md5()) {}
  };

  struct HmacMd5Digest : public HmacDigest
  {
    HmacMd5Digest(const std::string& key, const std::string& value) :
      HmacDigest(EVP_md5(), key, value) {}
  };

  template<typename ITERATOR>
  std::string md5(ITERATOR begin, ITERATOR end)
  {
    return Md5Digest().insert(begin, end).to_string();
  }

  std::string md5(const std::string& value);
}

#endif
