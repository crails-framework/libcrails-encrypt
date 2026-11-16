#include "secure_random.hpp"
#include <openssl/rand.h>
#include <crails/utils/backtrace.hpp>

using namespace std;

static string to_hex(unsigned char* bytes, size_t length)
{
  static const char digits[] = "0123456789abcdef";
  string output;

  output.reserve(length * 2);
  for (size_t i = 0 ; i < length ; ++i)
  {
    output += digits[bytes[i] >> 4];
    output += digits[bytes[i] & 0x0f];
  }
  return output;
}

namespace Crails
{
  string generate_random_token()
  {
    unsigned char bytes[32];

    if (RAND_bytes(bytes, sizeof(bytes)) != 1)
      throw boost_ext::runtime_error("no secure random source");
    return to_hex(bytes, sizeof(bytes));
  }

  string generate_random_code(size_t length)
  {
    string output;

    while (output.length() < length)
    {
      unsigned char byte;

      if (RAND_bytes(&byte, 1) != 1)
        throw boost_ext::runtime_error("no secure random source");
      if (byte < 250)
        output += static_cast<char>('0' + byte % 10);
    }
    return output;
  }
}
