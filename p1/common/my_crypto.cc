#include <cassert>
#include <iostream>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <vector>

#include "err.h"

using namespace std;

/// Run the AES symmetric encryption/decryption algorithm on a buffer of bytes.
/// Note that this will do either encryption or decryption, depending on how the
/// provided CTX has been configured.  After calling, the CTX cannot be used
/// again until it is reset.
///
/// @param ctx The pre-configured AES context to use for this operation
/// @param msg A buffer of bytes to encrypt/decrypt
///
/// @return A vector with the encrypted or decrypted result, or an empty
///         vector if there was an error
vector<uint8_t> aes_crypt_msg(EVP_CIPHER_CTX *ctx, const unsigned char *start,
                              int count) {
  // cout << count << endl;
  // These asserts are just for preventing compiler warnings:
  assert(ctx);
  assert(start);
  assert(count != -100);
  std::vector <uint8_t> v;
  std::vector<uint8_t>::iterator it;
  int byte_count=0, byte_read =0, byte_remain = count; 
  int cipher_block_size = EVP_CIPHER_block_size(EVP_CIPHER_CTX_cipher(ctx));
  const int BUFFSIZE=1024;
  unsigned char out_buf[BUFFSIZE + cipher_block_size];
  // iteratively encrpt/decrypt start until remain < 1024
  while(byte_remain >= 1024) {
    if (!EVP_CipherUpdate(ctx, out_buf, &byte_count, (start+byte_read), BUFFSIZE)) { 
      fprintf(stderr, "Error in EVP_CipherUpdate: %s\n",
              ERR_error_string(ERR_get_error(), nullptr));
      return {};
    }
    byte_remain -= BUFFSIZE;
    byte_read += BUFFSIZE;
    it = v.end(); // reset up the iterator to the end of v
    v.insert(it, out_buf, out_buf+byte_count);
    // cout << v.size() << endl;
  }
  // encrpt/decrpt the remainder of bytes
  if (!EVP_CipherUpdate(ctx, out_buf, &byte_count, (start+byte_read), byte_remain)) { 
    fprintf(stderr, "Error in EVP_CipherUpdate: %s\n",
            ERR_error_string(ERR_get_error(), nullptr));
    return {};
  }
  it = v.end(); // set iterator to the end of v
  v.insert(it,out_buf, out_buf+byte_count);
  // cout << v.size() << endl;
  // The final block needs special attention!
  if (!EVP_CipherFinal_ex(ctx, out_buf, &byte_count)) {
    fprintf(stderr, "Error in EVP_CipherFinal_ex: %s\n",
            ERR_error_string(ERR_get_error(), nullptr));
    return {};
  }
  v.insert(v.end(),out_buf, out_buf+byte_count);
  // cout << v.size() << endl;
  return v;
}
