#include <crails/pbkdf2_hmac.hpp>
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

int main()
{
  Crails::Pbkdf2HmacDigest digest("1234", "aaaaaaaaaaaaaaaaaaaaae", EVP_sha512());

  assert(digest.to_base64() == "oK2/hfypbsTy7FRSmPrbYmwGNiJWdlZWADA9fJCODTOwsv1XncvEU+3H6gAjFemc7wyaNOC+9wbMa0W976GNcA==");

  const string hash = digest.password_hash();

  assert(hash == "$pbkdf2-sha512$4096$YWFhYWFhYWFhYWFhYWFhYWFhYWFhZQ==$oK2/hfypbsTy7FRSmPrbYmwGNiJWdlZWADA9fJCODTOwsv1XncvEU+3H6gAjFemc7wyaNOC+9wbMa0W976GNcA==");

  // The default constructor, and the default iteration count
  Crails::Pbkdf2HmacDigest defaulted("1234", "aaaaaaaaaaaaaaaaaaaaae");

  assert(Crails::Pbkdf2HmacDigest::default_iteration_count == 4096);
  assert(defaulted.password_hash() == hash);

  // Custom iteration count (reference values from Python's hashlib.pbkdf2_hmac)
  Crails::Pbkdf2HmacDigest custom("1234", "aaaaaaaaaaaaaaaaaaaaae", 1000);

  assert(custom.to_base64() == "zSt54H5U+6ugK3BJjoQ0LBPsagbIf+oJwZ+iugFMTaU/ZqmdGFMoo7sEiMEeHuF2vaenoPe+fkhhFQ2QENLCZA==");
  assert(custom.password_hash() == "$pbkdf2-sha512$1000$YWFhYWFhYWFhYWFhYWFhYWFhYWFhZQ==$zSt54H5U+6ugK3BJjoQ0LBPsagbIf+oJwZ+iugFMTaU/ZqmdGFMoo7sEiMEeHuF2vaenoPe+fkhhFQ2QENLCZA==");

  // Custom iteration count with another digest
  Crails::Pbkdf2HmacDigest sha256("1234", "aaaaaaaaaaaaaaaaaaaaae", 2000, EVP_sha256());

  assert(sha256.to_string() == "f1505d24ba2a562ffdd073b1b3c48932c66a128517e3e9f0ab62327a8dd6a0bfb4d8f9e796dc74a7f250279eee6e4ee394cdff53d62070f4269e97a307195255");
  assert(sha256.password_hash().rfind("$pbkdf2-sha256$2000$", 0) == 0);

  // Nonsensical iteration count is reported instead of yielding an uninitialized digest
  const unsigned int no_iteration = 0;
  assert(throws([&]() { Crails::Pbkdf2HmacDigest("1234", "aaaaaaaaaaaaaaaaaaaaae", no_iteration); }));

  return 0;
}
