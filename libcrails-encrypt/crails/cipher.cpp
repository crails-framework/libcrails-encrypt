// ================================================================
// $Id: cipher.cc,v 1.1 2012/04/10 01:37:54 jlinoff Exp jlinoff $
//
// Description: Cipher class.
// Copyright:   Copyright (c) 2012 by Joe Linoff
// Version:     1.1
// Author:      Joe Linoff
//
// LICENSE
//   The cipher package is free software; you can redistribute it and/or
//   modify it under the terms of the GNU General Public License as
//   published by the Free Software Foundation; either version 2 of the
//   License, or (at your option) any later version.
//       
//   The cipher package is distributed in the hope that it will be useful,
//   but WITHOUT ANY WARRANTY; without even the implied warranty of
//   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//   General Public License for more details. You should have received
//   a copy of the GNU General Public License along with the change
//   tool; if not, write to the Free Software Foundation, Inc., 59
//   Temple Place, Suite 330, Boston, MA 02111-1307 USA.
// ================================================================
#include "cipher.hpp"
#include <fstream>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <stdexcept>
#include <sstream>
#include <cstring>        // strlen
#include <cstdlib>        // getenv
#include <unistd.h>       // getdomainname
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <crails/utils/backtrace.hpp>
#include <mutex>
#include <thread>
#ifdef _WIN32
# define bzero(b,len) (memset((b), '\0', (len)), (void)0)
#endif

typedef unsigned int uint;
typedef unsigned char uchar;

using namespace std;

// ================================================================
// MACROS
// ================================================================
#ifdef LIBCRAILSENCRYPT_DEBUG_MODE
# define DBG_PRE __FILE__ << ":" << __LINE__ << ": "
# define DBG_FCT(fct)   cout << DBG_PRE << "FCT " << fct << endl
# define DBG_TDUMP(v)   tdump(__FILE__,__LINE__,#v,v)
# define DBG_PKV(v)     vdump(__FILE__,__LINE__,#v,v)
# define DBG_BDUMP(a,x) bdump(__FILE__,__LINE__,#a,a,x)
# define DBG_MDUMP(a)   bdump(__FILE__,__LINE__,#a,(unsigned char*)a.c_str(),a.size())
#else
# define DBG_FCT(fct)
# define DBG_TDUMP(v)
# define DBG_PKV(v)
# define DBG_BDUMP(a,x)
# define DBG_MDUMP(a)
#endif

#define SALTED_PREFIX      "Salted__"

//
// Protects OpenSSL against concurrency
//
static void locking_function(std::mutex* mutexes, int mode, int n, const char*, int)
{
  if (mode & CRYPTO_LOCK)
    mutexes[n].lock();
  else
    mutexes[n].unlock();
}

static unsigned long id_function(void)
{
  return (unsigned long)std::hash<std::thread::id>() (std::this_thread::get_id());
}

void Cipher::initialize()
{
  static std::mutex* mutexes = new std::mutex[CRYPTO_num_locks()];

  CRYPTO_set_id_callback(id_function);
  CRYPTO_set_locking_callback(std::bind(locking_function, mutexes));
}
//
// END protects OpenSSL against concurrency
//

namespace
{
  // ================================================================
  // DEBUG mode only.
  // Formated dump of a general type.
  // ================================================================
  template<typename T> void vdump(const string& fn,
                                  uint ln,
                                  const string& prefix,
                                  const T& d)
  {
    cout << fn << ":" << ln << ": " << prefix << "\t" << d << endl;
  }
  // ================================================================
  // DEBUG mode only.
  // Explicit template instantiation of the above for string
  // types so that I can report the length.
  // ================================================================
  template<> void vdump<string>(const string& fn,
                      uint ln,
                      const string& prefix,
                      const string& d)
  {
    cout << fn << ":" << ln << ": " 
         << prefix << "\t" 
         << left << setw(64) << d 
         << " (" << d.size() << ")"
         << endl;
  }
  // ================================================================
  // DEBUG mode only.
  // Dump for fixed sized types like m_salt and m_key.
  // ================================================================
  template<typename T> void tdump(const string& fn,
                                  uint ln,
                                  const string& prefix,
                                  const T& d)
  {
    cout << fn << ":" << ln << ": " << prefix << "\t";
    for(uint i=0;i<sizeof(T);++i) {
#if 0
      // Prettified output.
      // I turned it off so that the format would match openssl.
      if ((i%16)==0) {
        if (i) {
          cout << endl;
          cout << "\t\t\t";
        }
        else {
          if (prefix.size()<4) {
            cout << "\t";
          }
          cout << "\t";
        }
      }
      else if (i) {
        cout << ", ";
      }
#endif
      cout << setw(2) << setfill('0') << hex << right << uint(d[i]) << dec << setfill(' ');
    }
    cout << " (" << sizeof(T) << ")" << endl;
  }
  // ================================================================
  // DEBUG mode only.
  // Binary data dump.
  // ================================================================
  void bdump(const string& fn,
             uint ln,
             const string& prefix,
             unsigned char* a,
             unsigned int len)
  {
    cout << fn << ":" << ln << ": " << prefix;
    for(uint i=0;i<len;++i) {
      if ((i%16)==0) {
        if (i) {
          cout << endl;
          cout << "\t\t\t";
        }
        else {
          cout << "\t\t";
        }
      }
      else if (i) {
        cout << ", ";
      }
      cout << setw(2) << hex << right << uint(a[i]) << dec;
    }
    cout << " (" << len << ")" << endl;
  }
}

struct EvpCipherCtxWrapper
{
  EVP_CIPHER_CTX* pointer;
  EvpCipherCtxWrapper()
  {
    pointer = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(pointer);
  }
  ~EvpCipherCtxWrapper()
  {
    EVP_CIPHER_CTX_free(pointer);
  }
};

// ================================================================
// Constructor.
// ================================================================
Cipher::Cipher()
  : m_cipher(CIPHER_DEFAULT_CIPHER),
    m_digest(CIPHER_DEFAULT_DIGEST),
    m_count(CIPHER_DEFAULT_COUNT),
    m_embed(true) // compatible with openssl
{
}

// ================================================================
// Constructor.
// ================================================================
Cipher::Cipher(const std::string& cipher,
               const std::string& digest,
               uint count,
               bool embed)
  : m_cipher(cipher),
    m_digest(digest),
    m_count(count),
    m_embed(embed)
{
}

// ================================================================
// Destructor.
// ================================================================
Cipher::~Cipher()
{
}

// ================================================================
// encrypt
// ================================================================
string Cipher::encrypt(const string& plaintext,
                       const string& pass,
                       const string& salt)
{
  DBG_FCT("encrypt");
  set_salt(salt);
  init(pass);
  kv1_t  x     = encode_cipher(plaintext);
  uchar* ct    = x.first;
  uint   ctlen = x.second;
  DBG_BDUMP(ct,ctlen);

  string ret = encode_base64(ct,ctlen);
  delete [] ct;
  DBG_MDUMP(ret);
  return ret;
}
  
// ================================================================
// encrypt_file
// ================================================================
void Cipher::encrypt_file(const string& ifn,
                          const string& ofn,
                          const string& pass,
                          const string& salt)
{
  DBG_FCT("encrypt_file");
  string plaintext = file_read(ifn);
  string ciphertext = encrypt(plaintext,pass,salt);
  file_write(ofn,ciphertext,true);
}

// ================================================================
// decrypt
// ================================================================
string Cipher::decrypt(const string& mimetext,
                       const string& pass,
                       const string& salt)
{
  DBG_FCT("decrypt");
  kv1_t  x     = decode_base64(mimetext);
  uchar* ct    = x.first;
  uchar* ctbeg = ct;
  uint   ctlen = x.second;
  DBG_BDUMP(ct,ctlen);

  if (strncmp((const char*)ct,SALTED_PREFIX,8) == 0) {
    memcpy(m_salt,&ct[8],8);
    ct += 16;
    ctlen -= 16;
  }
  else {
    set_salt(salt);
  }
  init(pass);
  string ret = decode_cipher(ct,ctlen);
  delete [] ctbeg;
  DBG_MDUMP(ret);
  return ret;
}
  
// ================================================================
// decrypt_file
// ================================================================
void Cipher::decrypt_file(const string& ifn,
                          const string& ofn,
                          const string& pass,
                          const string& salt)
{
  DBG_FCT("decrypt_file");
  string ciphertext = file_read(ifn);
  string plaintext = decrypt(ciphertext,pass,salt);
  file_write(ofn,plaintext);
}

// ================================================================
// encode_base64
// ================================================================
string Cipher::encode_base64(uchar* ciphertext,
                             uint   ciphertext_len) const
{
  DBG_FCT("encode_base64");
  BIO* b64 = BIO_new(BIO_f_base64());
  BIO* bm  = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64,bm);
  if (BIO_write(b64,ciphertext,ciphertext_len)<2) {
    throw boost_ext::runtime_error("BIO_write() failed");
  }
  if (BIO_flush(b64)<1) {
    throw boost_ext::runtime_error("BIO_flush() failed");
  }
  BUF_MEM *bptr=0;
  BIO_get_mem_ptr(b64,&bptr);
  uint len=bptr->length;
  char* mimetext = new char[len+1];
  memcpy(mimetext, bptr->data, bptr->length-1);
  mimetext[bptr->length-1]=0;
  BIO_free_all(b64);

  string ret = mimetext;
  delete [] mimetext;
  return ret;
}

// ================================================================
// decode_base64
// ================================================================
Cipher::kv1_t Cipher::decode_base64(const string& mimetext) const
{
  DBG_FCT("decode_base64");
  kv1_t x;
  int SZ=mimetext.size(); // this will always be smaller
  x.first = new uchar[SZ];
  char* tmpbuf = new char[SZ+1];
  strcpy(tmpbuf,mimetext.c_str());
  BIO* b64 = BIO_new(BIO_f_base64());
  BIO* bm  = BIO_new_mem_buf(tmpbuf,mimetext.size());
  bm = BIO_push(b64,bm);
  x.second = BIO_read(bm,x.first,SZ);
  BIO_free_all(bm);
  delete [] tmpbuf;
  return x;
}

// ================================================================
// encode_cipher
// ================================================================
Cipher::kv1_t Cipher::encode_cipher(const string& plaintext) const
{
  DBG_FCT("encode_cipher");
  uint SZ=plaintext.size()+AES_BLOCK_SIZE+20;
  uchar* ciphertext = new uchar[SZ];
  bzero(ciphertext,SZ);
  uchar* pbeg = ciphertext;

  // This requires some explanation.
  // In order to be compatible with openssl, I need to append
  // 16 characters worth of information that describe the salt.
  // I found this in the openssl source code but I couldn't
  // find any associated documentation.
  uint off = 0;
  if (m_embed) {
    memcpy(&ciphertext[0],SALTED_PREFIX,8);
    memcpy(&ciphertext[8],m_salt,8);
    off = 16;
    ciphertext += off;
  }

  int ciphertext_len=0;
  int ciphertext_padlen=0;
  EvpCipherCtxWrapper ctx_wrapper;
  EVP_CIPHER_CTX* ctx = ctx_wrapper.pointer;

  if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, m_key, m_iv)) {
    throw boost_ext::runtime_error("EVP_EncryptInit_ex() failed");
  }
  EVP_CIPHER_CTX_set_key_length(ctx, EVP_MAX_KEY_LENGTH);

  uchar* p    = (uchar*)plaintext.c_str();
  uint   plen = plaintext.size();
  if (!EVP_EncryptUpdate(ctx,ciphertext,&ciphertext_len,p,plen)) {
    throw boost_ext::runtime_error("EVP_EncryptUpdate() failed");
  }

  uchar* pbuf = ciphertext+ciphertext_len; // pad at the end
  if (!EVP_EncryptFinal_ex(ctx,pbuf,&ciphertext_padlen)) {
    throw boost_ext::runtime_error("EVP_EncryptFinal_ex() failed");
  }

  ciphertext_len += ciphertext_padlen + off; // <off> for the Salted prefix
  return kv1_t(pbeg,ciphertext_len);
}

// ================================================================
// decode_cipher
// ================================================================
string Cipher::decode_cipher(uchar* ciphertext,
                             uint   ciphertext_len) const
{
  DBG_FCT("decode_cipher");
  uint SZ = ciphertext_len+20;
  uchar* plaintext = new uchar[SZ];
  bzero(plaintext,SZ);
  int plaintext_len = 0;
  EvpCipherCtxWrapper ctx_wrapper;
  EVP_CIPHER_CTX* ctx = ctx_wrapper.pointer;

  if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, m_key, m_iv)) {
    throw boost_ext::runtime_error("EVP_DecryptInit_ex() failed");
  }
  EVP_CIPHER_CTX_set_key_length(ctx, EVP_MAX_KEY_LENGTH);

  if (!EVP_DecryptUpdate(ctx,plaintext,&plaintext_len,ciphertext,ciphertext_len)) {
    throw boost_ext::runtime_error("EVP_DecryptUpdate() failed");
  }

  int plaintext_padlen=0;
  if (!EVP_DecryptFinal_ex(ctx,plaintext+plaintext_len,&plaintext_padlen)) {
    throw boost_ext::runtime_error("EVP_DecryptFinal_ex() failed");
  }
  plaintext_len += plaintext_padlen;
  plaintext[plaintext_len] = 0;
    
  string ret = (char*)plaintext;
  delete [] plaintext;
  return ret;
}
  
// ================================================================
// cvt_salt
// ================================================================
void Cipher::set_salt(const string& salt)
{
  DBG_FCT("set_salt");
  if (salt.length() == 0) {
    // Choose a random salt.
    for(uint i=0;i<sizeof(m_salt);++i) {
      m_salt[i] = rand() % 256;
    }
  }
  else if (salt.length() == 8) {
    memcpy(m_salt,salt.c_str(),8);
  }
  else if (salt.length()<8) {
    throw boost_ext::underflow_error("init(): salt is too short, must be 8 characters");
  }
  else if (salt.length()>8) {
    throw boost_ext::overflow_error("init(): salt is too long, must be 8 characters");
  }
}

// ================================================================
// init()
// ================================================================

void Cipher::init(const string& pass)
{
  DBG_FCT("init");
  // Use a default passphrase if the user didn't specify one.
  m_pass = pass;
  if (m_pass.empty() ) {
    // Default: ' deFau1t pASsw0rD'
    // Obfuscate so that a simple strings will not find it.
    char a[] = {' ','d','e','F','a','u','1','t',' ',
                'p','A','S','s','w','0','r','D',0};
    m_pass = a;
  }

  // Create the key and IV values from the passkey.
  bzero(m_key,sizeof(m_key));
  bzero(m_iv,sizeof(m_iv));
  OpenSSL_add_all_algorithms();
  const EVP_CIPHER* cipher = EVP_get_cipherbyname(m_cipher.c_str());
  const EVP_MD*     digest = EVP_get_digestbyname(m_digest.c_str());
  if (!cipher) {
    string msg = "init(): cipher does not exist "+m_cipher;
    throw boost_ext::runtime_error(msg);
  }
  if (!digest) {
    string msg = "init(): digest does not exist "+m_digest;
    throw boost_ext::runtime_error(msg);
  }

  int ks = EVP_BytesToKey(cipher,    // cipher type
                          digest,    // message digest
                          m_salt,    // 8 bytes
                          (uchar*)m_pass.c_str(), // pass value
                          m_pass.length(),
                          m_count,   // number of rounds
                          m_key,
                          m_iv);
  if (ks!=32) {
    throw boost_ext::runtime_error("init() failed: "
                        "EVP_BytesToKey did not return a 32 byte key");
  }

  DBG_PKV(m_pass);
  DBG_PKV(m_cipher);
  DBG_PKV(m_digest);
  DBG_TDUMP(m_salt);
  DBG_TDUMP(m_key);
  DBG_TDUMP(m_iv);
  DBG_PKV(m_count);
}

// ================================================================
// file_read
// ================================================================
string Cipher::file_read(const string& fn) const
{
  DBG_FCT("file_read");
  ifstream ifs(fn.c_str());
  if (!ifs) {
    string msg="Cannot read file '"+fn+"'";
    throw boost_ext::runtime_error(msg);
  }
  string str((istreambuf_iterator<char>(ifs)),
             istreambuf_iterator<char>());
  return str;
}

// ================================================================
// file_write
// ================================================================
void Cipher::file_write(const string& fn,const string& data,bool nl) const
{
  DBG_FCT("file_write");
  ofstream ofs(fn.c_str());
  if (!ofs) {
    string msg="Cannot write file '"+fn+"'";
    throw boost_ext::runtime_error(msg);
  }
  ofs << data;
  if (nl) {
    ofs << endl;
  }
  ofs.close();
}
