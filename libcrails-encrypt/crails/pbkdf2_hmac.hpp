#ifndef  CRAILS_PKBF2_HMAC_SHA512_HPP
# define CRAILS_PKBF2_HMAC_SHA512_HPP

# include "digest.hpp"
# include <string_view>

namespace Crails
{
  class Pbkdf2HmacDigest : public Digest
  {
    const unsigned int iteration_count;
    const std::string salt;
    const EVP_MD* digest;
  public:
    static constexpr unsigned int default_iteration_count = 4096;

    Pbkdf2HmacDigest(const std::string_view password, const std::string_view salt, const EVP_MD* = EVP_sha512());
    Pbkdf2HmacDigest(const std::string_view password, const std::string_view salt, unsigned int iteration_count, const EVP_MD* = EVP_sha512());
    Pbkdf2HmacDigest(const Pbkdf2HmacDigest&) = delete;

    std::string password_hash() const;
  };
}

#endif
