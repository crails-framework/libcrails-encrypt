#ifndef  CRAILS_MD5_HPP
# define CRAILS_MD5_HPP

# include <string>
# include "message_digest.hpp"

namespace Crails
{
  struct Md5Digest : public MessageDigest
  {
    Md5Digest() : MessageDigest(EVP_md5()) {}
  };

  template<typename ITERATOR>
  std::string md5(ITERATOR begin, ITERATOR end)
  {
    return Md5Digest().insert(begin, end).to_string();
  }

  std::string md5(const std::string& value);
}

#endif
