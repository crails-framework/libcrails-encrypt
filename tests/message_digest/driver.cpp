#include <crails/message_digest.hpp>
#include <iostream>

#undef NDEBUG
#include <cassert>

using namespace std;

int main()
{
  const string sha256_abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

  // FIPS 180-2 test vector, by name and by EVP_MD
  Crails::MessageDigest by_name("sha256");
  by_name << "abc";
  assert(by_name.to_string() == sha256_abc);

  Crails::MessageDigest by_evp(EVP_sha256());
  by_evp << "abc";
  assert(by_evp.to_string() == sha256_abc);

  // Input can be fed in several pieces, or one char at a time
  Crails::MessageDigest chunked("sha256");
  chunked << "a" << "bc";
  assert(chunked.to_string() == sha256_abc);

  Crails::MessageDigest chars("sha256");
  chars << 'a' << 'b' << 'c';
  assert(chars.to_string() == sha256_abc);

  Crails::MessageDigest iterated("sha256");
  string input = "abc";
  iterated.insert(input.begin(), input.end());
  assert(iterated.to_string() == sha256_abc);

  // Asking for the result twice returns the same value
  Crails::MessageDigest twice("sha256");
  twice << "abc";
  assert(twice.to_string() == twice.to_string());
  assert(twice.to_base64() == twice.to_base64());

  // Base64 of the 32 raw bytes
  Crails::MessageDigest base64("sha256");
  base64 << "abc";
  assert(base64.to_base64() == "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=");

  // Empty input
  Crails::MessageDigest empty("sha256");
  assert(empty.to_string().length() == 0);
  // If we encrypted empty strings, this would be the result, but we don't:
  //assert(empty.to_string() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

  // Digest can be reused after being read
  Crails::MessageDigest reused("sha256");
  string output;
  reused << "abc";
  reused >> output;
  assert(output == sha256_abc);
  reused << "abc";
  assert(reused.to_string() == sha256_abc);

  try
  {
    Crails::MessageDigest unknown("no-such-digest");
    assert(false);
  }
  catch (const std::exception&) {}
  return 0;
}
