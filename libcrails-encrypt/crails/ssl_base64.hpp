#ifndef  CRAILS_SSL_BASE64_HPP
# define CRAILS_SSL_BASE64_HPP

# include <openssl/evp.h>
# include <cctype>
# include <stdexcept>
# include <string>
# include <string_view>

namespace Crails
{
  inline std::string ssl_base64_encode(std::string_view in, bool padded = true)
  {
    std::string out(4 * ((in.size() + 2) / 3) + 1, '\0'); // + NUL written by OpenSSL
    int length = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()),
                                 reinterpret_cast<const unsigned char*>(in.data()), in.size());

    out.resize(length);
    while (!padded && !out.empty() && out.back() == '=')
      out.pop_back();
    return out;
  }

  inline std::string ssl_base64_decode(std::string_view in)
  {
    while (!in.empty() && std::isspace(static_cast<unsigned char>(in.back())))
      in.remove_suffix(1);
    if (in.empty() || in.size() % 4 == 1)
      throw std::runtime_error("invalid base64 input");

    std::string padded(in);
    while (padded.size() % 4 != 0)
      padded += '=';

    std::string out(padded.size() / 4 * 3, '\0');
    int length = EVP_DecodeBlock(reinterpret_cast<unsigned char*>(out.data()),
                                 reinterpret_cast<const unsigned char*>(padded.data()), padded.size());

    for (size_t i = padded.size() ; i > 0 && padded[i - 1] == '=' ; --i)
      --length;
    if (length < 0)
      throw std::runtime_error("invalid base64 input");
    out.resize(length);
    return out;
  }
}

#endif
