#ifndef  CRAILS_MESSAGE_DIGEST_HPP
# define CRAILS_MESSAGE_DIGEST_HPP

# include "digest.hpp"

namespace Crails
{
  class MessageDigest : public Digest
  {
    EVP_MD_CTX*   context;
    const EVP_MD* md;
    bool          initialized =  false;
  public:
    MessageDigest(const EVP_MD* md);
    MessageDigest(const std::string& strategy);
    MessageDigest(const MessageDigest&) = delete;
    virtual ~MessageDigest();

    MessageDigest& operator<<(const std::string& input);
    MessageDigest& operator>>(std::string& output);

    std::string to_string();
    std::string to_base64();

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
