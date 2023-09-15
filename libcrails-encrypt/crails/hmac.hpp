#ifndef  CRAILS_HMAC_HPP
# define CRAILS_HMAC_HPP

# include "digest.hpp"

namespace Crails
{
  class HmacDigest : public Digest
  {
  public:
    HmacDigest(const EVP_MD*, const std::string& key, const std::string& message);
    HmacDigest(const HmacDigest&) = delete;
  };
}

#endif
