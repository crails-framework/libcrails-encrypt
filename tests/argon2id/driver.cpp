#include <crails/argon2id.hpp>
#include <iostream>

#undef NDEBUG
#include <cassert>

using namespace std;
using Crails::Argon2idDigest;
using Crails::Argon2idParameters;

// Reference values generated with argon2-cffi (libargon2), to check interoperability.
static const string salt = "somesaltsomesalt";
static const string reference_hash = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$K13EBUiG7JV+9ZxztmHFTdb7J0WQsnj2V8bZaqyPptE";
static const string reference_hex  = "2b5dc4054886ec957ef59c73b661c54dd6fb274590b278f657c6d96aac8fa6d1";
static const string custom_hash    = "$argon2id$v=19$m=8192,t=3,p=2$c29tZXNhbHRzb21lc2FsdA$JrXX/b2HEVtjeHpW0TOgX7LnW+ePVlX5KCVDdpGaMgg";
static const string foreign_hash   = "$argon2id$v=19$m=19456,t=2,p=1$HtO3S3XhCT26wFOmUFOJPg$paIk9HK6uzzkxOAEo3sQ8pKtE0tqGvzQHSKARvY0Tbo";

template<typename FUNCTION>
static bool throws(FUNCTION function)
{
  try { function(); } catch (const exception&) { return true; }
  return false;
}

void known_answer_test()
{
  Argon2idDigest digest("password", salt);

  assert(digest.password_hash() == reference_hash);
  assert(digest.to_string() == reference_hex);

  Argon2idDigest custom("correct horse battery staple", salt, Argon2idParameters{8192, 3, 2});

  assert(custom.password_hash() == custom_hash);
}

void verify_test()
{
  assert(Argon2idDigest::verify("password", reference_hash));
  assert(!Argon2idDigest::verify("Password", reference_hash));
  assert(!Argon2idDigest::verify("", reference_hash));
  assert(Argon2idDigest::verify("correct horse battery staple", custom_hash));
  assert(!Argon2idDigest::verify("password", custom_hash));
  assert(Argon2idDigest::verify("hunter2", foreign_hash));
  assert(!Argon2idDigest::verify("hunter3", foreign_hash));
}

void random_salt_test()
{
  Argon2idDigest first("password"), second("password");
  const string hash = first.password_hash();

  assert(hash != second.password_hash());
  assert(hash.rfind("$argon2id$v=19$m=19456,t=2,p=1$", 0) == 0);
  assert(Argon2idDigest::verify("password", hash));
  assert(Argon2idDigest::verify("password", second.password_hash()));
  assert(!Argon2idDigest::verify("other", hash));
}

void malformed_hash_test()
{
  for (const string& hash : {
    string(""),
    string("garbage"),
    string("$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA"),                                    // no hash field
    string("$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$K13EBUiG7JV+9ZxztmHFTdb7J0WQsnj2V8bZaqyPptE$extra"),
    string("$argon2i$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$K13EBUiG7JV+9ZxztmHFTdb7J0WQsnj2V8bZaqyPptE"),
    string("$argon2id$v=16$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$K13EBUiG7JV+9ZxztmHFTdb7J0WQsnj2V8bZaqyPptE"),
    string("$argon2id$v=19$m=abc,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$K13EBUiG7JV+9ZxztmHFTdb7J0WQsnj2V8bZaqyPptE"),
    string("$argon2id$v=19$m=19456,t=2$c29tZXNhbHRzb21lc2FsdA$K13EBUiG7JV+9ZxztmHFTdb7J0WQsnj2V8bZaqyPptE"),
    string("$argon2id$v=19$m=19456,t=2,p=1,x=3$c29tZXNhbHRzb21lc2FsdA$K13EBUiG7JV+9ZxztmHFTdb7J0WQsnj2V8bZaqyPptE"),
    string("$argon2id$v=19$m=19456,t=2,p=1$!!!!$K13EBUiG7JV+9ZxztmHFTdb7J0WQsnj2V8bZaqyPptE"),            // invalid base64 salt
    string("$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$K13EBUiG7JV+9Zxz"),                    // hash too short
  })
    assert(!Argon2idDigest::verify("password", hash));
}

void invalid_parameters_test()
{
  assert(throws([]() { Argon2idDigest("password", salt, Argon2idParameters{19456, 2, 0}); }));
  assert(throws([]() { Argon2idDigest("password", salt, Argon2idParameters{19456, 0, 1}); }));
  assert(throws([]() { Argon2idDigest("password", salt, Argon2idParameters{1, 2, 1}); }));    // memory < 8 * lanes
  assert(throws([]() { Argon2idDigest("password", "short", Argon2idParameters{}); }));         // salt < 8 bytes
}

int main()
{
#if OPENSSL_VERSION_NUMBER < 0x30200000L
  cerr << "argon2id test skipped: requires OpenSSL 3.2 or later" << endl;
  return 0;
#endif
  known_answer_test();
  verify_test();
  random_salt_test();
  malformed_hash_test();
  invalid_parameters_test();
  return 0;
}
