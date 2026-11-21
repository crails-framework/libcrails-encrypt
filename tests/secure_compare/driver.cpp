#include <crails/secure_compare.hpp>
#include <string>

#undef NDEBUG
#include <cassert>

using namespace std;
using Crails::secure_compare;

int main()
{
  assert(secure_compare("", ""));
  assert(secure_compare("abc", "abc"));
  assert(!secure_compare("abc", "abd"));  // last byte differs
  assert(!secure_compare("abc", "xbc"));  // first byte differs
  assert(!secure_compare("abc", "ab"));   // different lengths
  assert(!secure_compare("ab", "abc"));
  assert(!secure_compare("", "a"));

  // Embedded NUL bytes and high bytes are compared like any other
  assert(secure_compare(string("a\0b", 3), string("a\0b", 3)));
  assert(!secure_compare(string("a\0b", 3), string("a\0c", 3)));
  assert(!secure_compare("\xff", "\x7f"));
  return 0;
}
