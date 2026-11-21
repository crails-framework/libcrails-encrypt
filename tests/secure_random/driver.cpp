#include <crails/secure_random.hpp>
#include <algorithm>
#include <cctype>
#include <set>

#undef NDEBUG
#include <cassert>

using namespace std;

int main()
{
  // Tokens: 32 random bytes, hex encoded
  set<string> tokens;

  for (int i = 0 ; i < 100 ; ++i)
  {
    string token = Crails::generate_random_token();

    assert(token.length() == 64);
    assert(all_of(token.begin(), token.end(), [](unsigned char c) { return isxdigit(c) && !isupper(c); }));
    tokens.insert(token);
  }
  assert(tokens.size() == 100);

  // Codes: digits only, requested length
  assert(Crails::generate_random_code(0) == "");
  assert(Crails::generate_random_code(1).length() == 1);
  assert(Crails::generate_random_code(6).length() == 6);
  assert(Crails::generate_random_code(100).length() == 100);

  string digits_seen;
  for (int i = 0 ; i < 100 ; ++i)
  {
    string code = Crails::generate_random_code(100);

    assert(all_of(code.begin(), code.end(), [](unsigned char c) { return isdigit(c); }));
    digits_seen += code;
  }
  // 10000 draws: every digit must show up (failure odds ~ 1e-4500)
  for (char digit = '0' ; digit <= '9' ; ++digit)
    assert(digits_seen.find(digit) != string::npos);
  return 0;
}
