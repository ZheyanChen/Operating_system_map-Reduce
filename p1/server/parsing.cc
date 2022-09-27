#include <cassert>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <math.h>

#include "../common/contextmanager.h"
#include "../common/crypto.h"
#include "../common/err.h"
#include "../common/net.h"
#include "../common/protocol.h"

#include "parsing.h"
#include "responses.h"

using namespace std;

//convert 8 bytes hex to size_t (read in a vector)
static size_t bin2dec (const vector<uint8_t> &v) {
  size_t len =0;
  for (size_t i=0; i<v.size(); i++) {
    len += (size_t) v[i] * pow(256,i);
  }
  return len;
}

/// When a new client connection is accepted, this code will run to figure out
/// what the client is requesting, and to dispatch to the right function for
/// satisfying the request.
///
/// @param sd      The socket on which communication with the client takes place
/// @param pri     The private key used by the server
/// @param pub     The public key file contents, to possibly send to the client
/// @param storage The Storage object with which clients interact
///
/// @return true if the server should halt immediately, false otherwise
bool parse_request(int sd, RSA *pri, const vector<uint8_t> &pub,
                   Storage *storage) {
  // cout << "parsing.cc::parse_request() is not implemented\n";
  vector<uint8_t> enc_rblock (LEN_RKBLOCK);  // preallocate 256 bytes
  reliable_get_to_eof_or_n(sd,enc_rblock.begin(),LEN_RKBLOCK);  // populate the enc_rblock
  string cmd_status (enc_rblock.begin(),enc_rblock.begin()+REQ_KEY.length());
  if (!cmd_status.compare(REQ_KEY)) { // check for req_key 
   return handle_key(sd,pub);
  }   
  // other kinds of requestes
    vector<uint8_t> dec_rblock(RSA_size(pri));   // populate dec_rblock
    int recovered_bytes = RSA_private_decrypt(LEN_RKBLOCK,enc_rblock.data(),dec_rblock.data(),pri,RSA_PKCS1_OAEP_PADDING); 
    if (recovered_bytes == -1) {
      fprintf(stderr, "Error decrypting\n");
      return false;
    }
    size_t aes_len = AES_KEYSIZE + AES_IVSIZE;  // 48 bytes
    vector<uint8_t> cmd (dec_rblock.begin(),dec_rblock.begin()+8);   // fetch 8 byte cmd
    vector<uint8_t> aes_key (dec_rblock.begin()+8,dec_rblock.begin()+8+aes_len);  // fetch aes key
    vector<uint8_t> ablock_len_bin (dec_rblock.begin()+8+aes_len,dec_rblock.begin()+16+aes_len);  // fetch len of ablock in hex
    size_t ablock_len = bin2dec(ablock_len_bin);

    // enc_ablock vector
    vector<uint8_t> enc_ablock (ablock_len);   // preallocate ablock_len
    reliable_get_to_eof_or_n(sd,(vector<uint8_t>::iterator)enc_ablock.data(),ablock_len);
    EVP_CIPHER_CTX *ctx_dec = create_aes_context(aes_key,false);
    auto dec_ablock =aes_crypt_msg(ctx_dec,enc_ablock);
    reset_aes_context(ctx_dec,aes_key,true);      // reset ctx for encryption context
    string cmd_str (cmd.begin(), cmd.end());
    if (!cmd_str.compare(REQ_REG)) {     //  check for req_reg
      return handle_reg(sd,storage,ctx_dec,dec_ablock);
    }
    else if (!cmd_str.compare(REQ_BYE)) {     //  check for req_bye
      return handle_bye(sd,storage,ctx_dec,dec_ablock);
    }
    else if (!cmd_str.compare(REQ_SET)) {     //  check for req_set
      return handle_set(sd,storage,ctx_dec,dec_ablock);
    }    
    else if (!cmd_str.compare(REQ_GET)) {     //  check for req_get
      return handle_get(sd,storage,ctx_dec,dec_ablock);
    }
    else if (!cmd_str.compare(REQ_SAV)) {     //  check for req_sav
      return handle_sav(sd,storage,ctx_dec,dec_ablock);
    }
    else if (!cmd_str.compare(REQ_ALL)) {     //  check for req_all
      return handle_all(sd,storage,ctx_dec,dec_ablock);
    }

  // return false;
}
