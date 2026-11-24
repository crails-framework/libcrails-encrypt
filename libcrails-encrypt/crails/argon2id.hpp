#ifndef  CRAILS_ARGON2ID_HPP
# define CRAILS_ARGON2ID_HPP

# include "digest.hpp"
# include <string_view>

namespace Crails
{
  // OWASP's minimum recommendation (around 20-50 ms per hash, and 19 MiB of memory)
  struct Argon2idParameters
  {
    unsigned int memory_kib  = 19456;
    unsigned int iterations  = 2;
    unsigned int parallelism = 1;
  };

  class Argon2idDigest : public Digest
  {
    const Argon2idParameters parameters;
    const std::string salt;
  public:
    Argon2idDigest(const std::string_view password, const std::string_view salt, const Argon2idParameters& = {});
    Argon2idDigest(const std::string_view password, const Argon2idParameters& = {}); // uses a random salt
    Argon2idDigest(const Argon2idDigest&) = delete;

    std::string password_hash() const;

    static bool verify(const std::string_view password, const std::string_view stored_hash);
  };
}

#endif
