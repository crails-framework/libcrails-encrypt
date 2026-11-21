#include <crails/hmac.hpp>
#include <crails/md5.hpp>

#undef NDEBUG
#include <cassert>

using namespace std;

int main()
{
  // RFC 4231, test case 2
  Crails::HmacDigest sha256(EVP_sha256(), "Jefe", "what do ya want for nothing?");
  assert(sha256.to_string() == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

  // Same digest, selected by name
  Crails::HmacDigest by_name("sha256", "Jefe", "what do ya want for nothing?");
  assert(by_name.to_string() == sha256.to_string());
  assert(by_name.to_base64() == sha256.to_base64());

  // RFC 2202, test case 2
  Crails::HmacMd5Digest md5("Jefe", "what do ya want for nothing?");
  assert(md5.to_string() == "750c783e6ab0b503eaa86e310a5db738");

  // Key and message both matter
  assert(Crails::HmacDigest("sha256", "other key", "what do ya want for nothing?").to_string() != sha256.to_string());
  assert(Crails::HmacDigest("sha256", "Jefe", "other message").to_string() != sha256.to_string());

  try
  {
    Crails::HmacDigest("no-such-digest", "key", "message");
    assert(false);
  }
  catch (const std::exception&) {}
  return 0;
}
