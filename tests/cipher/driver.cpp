#include <crails/cipher.hpp>
#include <filesystem>
#include <iostream>

#undef NDEBUG
#include <cassert>

using namespace std;

template<typename FUNCTION>
static bool throws(FUNCTION function)
{
  try { function(); } catch (const exception&) { return true; }
  return false;
}

static const string pass = "testTEST!23_";
static const string plaintext = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";

void cipher_test()
{
  Cipher c;
  string ciphertext = c.encrypt(plaintext, pass);
  string decoded    = c.decrypt(ciphertext, pass);

  assert(plaintext == decoded);
  assert(ciphertext.find(plaintext) == string::npos);
}

void cipher_is_randomized_test()
{
  Cipher c;

  assert(c.encrypt(plaintext, pass) != c.encrypt(plaintext, pass));
}

void cipher_edge_cases_test()
{
  Cipher c;
  string binary("a\0b\0\xff", 5);

  assert(c.decrypt(c.encrypt("", pass), pass) == "");
  assert(c.decrypt(c.encrypt(binary, pass), pass) == binary);
  assert(c.decrypt(c.encrypt(string(100000, 'x'), pass), pass) == string(100000, 'x'));
}

void cipher_rejects_bad_input_test()
{
  Cipher c;
  string ciphertext = c.encrypt(plaintext, pass);
  string tampered = ciphertext;

  tampered[tampered.size() / 2] = tampered[tampered.size() / 2] == 'A' ? 'B' : 'A';
  assert(throws([&]() { c.decrypt(ciphertext, "wrong passphrase"); }));
  assert(throws([&]() { c.decrypt(tampered, pass); }));
  assert(throws([&]() { c.decrypt(ciphertext.substr(0, 20), pass); }));
  assert(throws([&]() { c.decrypt("", pass); }));
  assert(throws([&]() { c.decrypt("not base64 at all!", pass); }));
  assert(throws([&]() { c.encrypt(plaintext, ""); }));
  assert(throws([&]() { c.decrypt(ciphertext, ""); }));
}

void cipher_iterations_test()
{
  for (unsigned int iterations : {Cipher::HighEntropyKey, Cipher::ApplicationSecret})
  {
    Cipher c(iterations);

    assert(c.decrypt(c.encrypt(plaintext, pass), pass) == plaintext);
  }
  // The work factor is part of the key: it must match on both sides.
  assert(throws([]() {
    Cipher(Cipher::HighEntropyKey).decrypt(Cipher(Cipher::ApplicationSecret).encrypt(plaintext, pass), pass);
  }));
}

int main()
{
  cipher_test();
  cipher_is_randomized_test();
  cipher_edge_cases_test();
  cipher_rejects_bad_input_test();
  cipher_iterations_test();
  return 0;
}

