#include <crails/cipher.hpp>
#include <iostream>

#undef NDEBUG
#include <cassert>

void cipher_test()
{                                                                                                             
  using namespace std;
  string pass = "testTEST!23_"; 
  string salt = "12345678"; // must be 8 chars
  string plaintext = "Lorem ipsum dolor sit amet, consectetur adipiscing elit."; 

  // Encrypt and decrypt.
  Cipher c;
  string ciphertext = c.encrypt(plaintext ,pass,salt);
  string decoded    = c.decrypt(ciphertext,pass,salt);

  // Test the results                                                                                        
  assert(plaintext == decoded);
}

int main()
{
  Cipher::initialize();

  cipher_test();
  return 0;
}

