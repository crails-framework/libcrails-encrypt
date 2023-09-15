#ifndef  CRAILS_DIGEST_HPP
# define CRAILS_DIGEST_HPP

# include <openssl/evp.h>
# include <string>

namespace Crails
{
  class Digest
  {
  protected:
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int  md_len;
  public:
    std::string to_string();
    std::string to_base64();
  };
}

#endif
