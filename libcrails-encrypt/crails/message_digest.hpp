#ifndef  CRAILS_MESSAGE_DIGEST_HPP
# define CRAILS_MESSAGE_DIGEST_HPP

# include <openssl/evp.h>
# include <string>

namespace Crails
{
  class MessageDigest
  {
    EVP_MD_CTX*   context;
    const EVP_MD* md;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int  md_len;
    bool          initialized =  false;
  public:
    MessageDigest(const EVP_MD* md);
    MessageDigest(const std::string& strategy);
    virtual ~MessageDigest();

    MessageDigest& operator<<(const std::string& input);
    MessageDigest& operator>>(std::string& output);

    std::string to_string();

    template<typename ITERATOR>
    MessageDigest& insert(ITERATOR begin, ITERATOR end)
    {
      for (; begin != end ; ++begin)
        operator<<(*begin);
      return *this;
    }

  private:
    void initialize();
    void finalize();
  };
}

#endif
