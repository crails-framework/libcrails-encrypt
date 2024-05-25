#include <crails/pbkdf2_hmac.hpp>
#include <iostream>

#undef NDEBUG
#include <cassert>

using namespace std;

int main()
{
  Crails::Pbkdf2HmacDigest digest("1234", "aaaaaaaaaaaaaaaaaaaaae", EVP_sha512());

  assert(digest.to_base64() == "oK2/hfypbsTy7FRSmPrbYmwGNiJWdlZWADA9fJCODTOwsv1XncvEU+3H6gAjFemc7wyaNOC+9wbMa0W976GNcA==");

  const string hash = digest.password_hash();

  assert(hash == "$pbkdf2-sha512$4096$YWFhYWFhYWFhYWFhYWFhYWFhYWFhZQ==$oK2/hfypbsTy7FRSmPrbYmwGNiJWdlZWADA9fJCODTOwsv1XncvEU+3H6gAjFemc7wyaNOC+9wbMa0W976GNcA==");

  return 0;
}
