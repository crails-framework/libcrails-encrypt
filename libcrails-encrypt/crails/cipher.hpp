#ifndef  CRAILS_CIPHER_HPP
# define CRAILS_CIPHER_HPP

# include <string>

/**
 * Authenticated encryption: AES-256-GCM, key derived using PBKDF2-HMAC-SHA256 and random salt.
 * Fresh salt and nonce are generated for every call to encrypt().
 * Output layout (base64-encoded): version(1) | salt(16) | nonce(12) | ciphertext | tag(16)
 */
class Cipher
{
public:
  /**
   * PBKDF2 work factor, depending on what the passphrase is:
   * - HighEntropyKey:    random secret (cookies, tokens): stretching adds nothing, so no cost.
   * - ApplicationSecret: human-chosen secret stored in a config file (~2ms).
   * - UserPassphrase:    passphrase typed by a person (~150ms), OWASP recommendation for SHA-256.
   * Cipher must use the same iterations count to decrypt something that was encrypted with a given count.
   */
  enum Iterations : unsigned int
  {
    HighEntropyKey    = 1,     // Random secrets (cookies, token), low cost
    ApplicationSecret = 10000, // ~2ms
    UserPassphrase    = 600000 // ~150ms, following OWASP recommendation for passwords
  };

  explicit Cipher(unsigned int iterations = HighEntropyKey) : iterations(iterations) {}

  std::string encrypt(const std::string& plaintext, const std::string& pass) const;
  std::string decrypt(const std::string& ciphertext, const std::string& pass) const;

private:
  unsigned int iterations;
};

#endif
