#include <crails/md5.hpp>
#include <vector>

#undef NDEBUG
#include <cassert>

int main()
{
  Crails::Md5Digest stream;
  std::string output;
  std::vector<unsigned char> array{'T', 'o', 't', 'o', 'c', 'a', 'c', 'a'};

  stream << "Coucou petite perruche";
  assert(stream.to_string() == "20e5162f63f003e61da57127db9750dd");

  stream << "Totocaca";
  stream >> output;
  assert(output == "f18ceddb60703f7a6b5bae05b60d631f");

  stream << "Coucou petite perruche";
  stream << "Totocaca";
  stream >> output;
  assert(output == "3e9f18352fb4dc27a2d7fdfa0510703f");

  assert(Crails::md5("Coucou petite perruche") == "20e5162f63f003e61da57127db9750dd");
  assert(Crails::md5(array.begin(), array.end()) == "f18ceddb60703f7a6b5bae05b60d631f");

  return 0;
}
