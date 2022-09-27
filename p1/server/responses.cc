#include <cassert>
#include <iostream>
#include <string>
#include <math.h>

#include "../common/crypto.h"
#include "../common/net.h"

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

// convert size_t len to vector of uint8_t
vector<uint8_t> convert_len_to_hex (size_t len) {
  vector<uint8_t> hex;
  hex.insert(hex.end(),(uint8_t*)&len,((uint8_t*)&len)+sizeof(len));  // read 8 bytes of char 
  return hex;
}

/// Respond to an ALL command by generating a list of all the usernames in the
/// Auth table and returning them, one per line.
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @return false, to indicate that the server shouldn't stop
bool handle_all(int sd, Storage *storage, EVP_CIPHER_CTX *ctx,
                const vector<uint8_t> &req) {
  // cout << "responses.cc::handle_all() is not implemented\n";
  // NB: These asserts are to prevent compiler warnings
  vector<uint8_t> user_bin (req.begin(),req.begin()+8);
  vector<uint8_t> pass_bin (req.begin()+8,req.begin()+16);
  size_t user_len = bin2dec(user_bin);
  size_t pass_len = bin2dec(pass_bin);
  vector<uint8_t>::const_iterator it = req.begin() + AES_KEYSIZE;  // it is at 32 bytes
  string user (it, it+user_len);
  string pass (it+user_len, it+user_len+pass_len);
  auto all_tuple = storage -> get_all_users(user,pass);
  vector<uint8_t> msg (all_tuple.msg.begin(),all_tuple.msg.end());
  if (all_tuple.succeeded) {  //autenthicated 
    auto all_bin = convert_len_to_hex(all_tuple.data.size());
    msg.insert(msg.end(),all_bin.begin(),all_bin.end());
    msg.insert(msg.end(),all_tuple.data.begin(),all_tuple.data.end());
  }
  auto enc_msg = aes_crypt_msg(ctx,msg);
  send_reliably(sd,enc_msg);
  return false;
}

/// Respond to a SET command by putting the provided data into the Auth table
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @return false, to indicate that the server shouldn't stop
bool handle_set(int sd, Storage *storage, EVP_CIPHER_CTX *ctx,
                const vector<uint8_t> &req) {
  // cout << "responses.cc::handle_set() is not implemented\n";
  // NB: These asserts are to prevent compiler warnings
  vector<uint8_t> user_bin (req.begin(),req.begin()+8);
  vector<uint8_t> pass_bin (req.begin()+8,req.begin()+16);
  vector<uint8_t> prof_bin (req.begin()+16,req.begin()+24);
  size_t user_len = bin2dec(user_bin);
  size_t pass_len = bin2dec(pass_bin);
  size_t prof_len = bin2dec(prof_bin);
  vector<uint8_t>::const_iterator it = req.begin() + AES_KEYSIZE;  // it is at 32 bytes
  string user (it, it+user_len);
  string pass (it+user_len, it+user_len+pass_len);
  vector <uint8_t> profile (it+user_len+pass_len, it+user_len+pass_len+prof_len);
  // authenticate user info
  Storage::result_t auth = storage ->auth(user,pass);
  if (auth.succeeded) {
    storage -> set_user_data(user,pass,profile);
  }
  auto res = aes_crypt_msg(ctx,auth.msg);
  send_reliably(sd, res);
  return false;
}

/// Respond to a GET command by getting the data for a user
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @return false, to indicate that the server shouldn't stop
bool handle_get(int sd, Storage *storage, EVP_CIPHER_CTX *ctx,
                const vector<uint8_t> &req) {
  // cout << "responses.cc::handle_get() is not implemented\n";
  // NB: These asserts are to prevent compiler warnings
  vector<uint8_t> user_bin (req.begin(),req.begin()+8);
  vector<uint8_t> pass_bin (req.begin()+8,req.begin()+16);
  vector<uint8_t> who_bin (req.begin()+16,req.begin()+24);
  size_t user_len = bin2dec(user_bin);
  size_t pass_len = bin2dec(pass_bin);
  size_t who_len = bin2dec(who_bin);
  vector<uint8_t>::const_iterator it = req.begin() + AES_KEYSIZE;  // it is at 32 bytes
  string user (it, it+user_len);
  string pass (it+user_len, it+user_len+pass_len);
  string who (it+user_len+pass_len, it+user_len+pass_len+who_len);
  
  // authenticate user info

  Storage::result_t who_tuple = storage -> get_user_data(user,pass,who);
  vector<uint8_t> msg;
  msg.insert(msg.end(),who_tuple.msg.begin(),who_tuple.msg.end()); // insert OK / or any error
  if (who_tuple.succeeded) {
    auto who_bin = convert_len_to_hex(who_tuple.data.size());  // vector of who's content length in hex
    msg.insert(msg.end(),who_bin.begin(),who_bin.end());  // insert who_bin
    msg.insert(msg.end(),who_tuple.data.begin(),who_tuple.data.end()); // insert who's content
  }
  auto enc_msg = aes_crypt_msg(ctx,msg);
  send_reliably(sd, enc_msg);  // send enc_msg to client
  return false;
}

/// Respond to a REG command by trying to add a new user
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @return false, to indicate that the server shouldn't stop
bool handle_reg(int sd, Storage *storage, EVP_CIPHER_CTX *ctx,
                const vector<uint8_t> &req) {
  // NB: These asserts are to prevent compiler warnings
  vector<uint8_t> user_bin (req.begin(),req.begin()+8);
  vector<uint8_t> pass_bin (req.begin()+8,req.begin()+16);
  size_t user_len = bin2dec(user_bin);
  size_t pass_len = bin2dec(pass_bin);
  vector<uint8_t>::const_iterator it = req.begin() + AES_KEYSIZE;  // it is at 32 bytes
  string user (it, it+user_len);
  string pass (it+user_len, it+user_len+pass_len);
  // storing info back to storage obj
  Storage::result_t storage_res = storage ->add_user(user,pass);
  auto res = aes_crypt_msg(ctx,storage_res.msg);
  send_reliably(sd, res);
  return false;
}

/// In response to a request for a key, do a reliable send of the contents of
/// the pubfile
///
/// @param sd The socket on which to write the pubfile
/// @param pubfile A vector consisting of pubfile contents
///
/// @return false, to indicate that the server shouldn't stop
bool handle_key(int sd, const vector<uint8_t> &pubfile) {
  // cout << "responses.cc::handle_key() is not implemented\n";
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(pubfile.size() > 0);
  send_reliably(sd,pubfile);
  return false;
}

/// Respond to a BYE command by returning false, but only if the user
/// authenticates
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @return true, to indicate that the server should stop, or false on an error
bool handle_bye(int sd, Storage *storage, EVP_CIPHER_CTX *ctx,
                const vector<uint8_t> &req) {
  // cout << "responses.cc::handle_bye() is not implemented\n";
  // NB: These asserts are to prevent compiler warnings
  vector<uint8_t> user_bin (req.begin(),req.begin()+8);
  vector<uint8_t> pass_bin (req.begin()+8,req.begin()+16);
  size_t user_len = bin2dec(user_bin);
  size_t pass_len = bin2dec(pass_bin);
  vector<uint8_t>::const_iterator it = req.begin() + AES_KEYSIZE;  // it is at 32 bytes
  string user (it, it+user_len);
  string pass (it+user_len, it+user_len+pass_len);
  // authenticate user with info
  Storage::result_t auth = storage ->auth(user,pass);
  auto res = aes_crypt_msg(ctx,auth.msg);
  send_reliably(sd, res);
  if (auth.succeeded) {storage->shutdown();return true;}
  else return false;
}

/// Respond to a SAV command by persisting the file, but only if the user
/// authenticates
///
/// @param sd      The socket onto which the result should be written
/// @param storage The Storage object, which contains the auth table
/// @param ctx     The AES encryption context
/// @param req     The unencrypted contents of the request
///
/// @return false, to indicate that the server shouldn't stop
bool handle_sav(int sd, Storage *storage, EVP_CIPHER_CTX *ctx,
                const vector<uint8_t> &req) {
  // cout << "responses.cc::handle_sav() is not implemented\n";
  // NB: These asserts are to prevent compiler warnings
  vector<uint8_t> user_bin (req.begin(),req.begin()+8);
  vector<uint8_t> pass_bin (req.begin()+8,req.begin()+16);
  size_t user_len = bin2dec(user_bin);
  size_t pass_len = bin2dec(pass_bin);
  vector<uint8_t>::const_iterator it = req.begin() + AES_KEYSIZE;  // it is at 32 bytes
  string user (it, it+user_len);
  string pass (it+user_len, it+user_len+pass_len);
  // authenticate user with info
  Storage::result_t auth = storage ->auth(user,pass);
  if (auth.succeeded) {
    storage->save_file();  // call storage save file when authenticated
  }
  auto res = aes_crypt_msg(ctx,auth.msg);
  send_reliably(sd,res);
  return false;
}
