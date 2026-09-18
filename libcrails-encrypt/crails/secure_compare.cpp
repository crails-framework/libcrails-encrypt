#include "secure_compare.hpp"

using namespace std;

bool Crails::secure_compare(const string_view a, const string_view b)
{
  if (a.length() == b.length())
  {
    unsigned char diff = 0;

    for (size_t i = 0 ; i < a.length() ; ++i)
      diff |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
    return diff == 0;
  }
  return false;
}
