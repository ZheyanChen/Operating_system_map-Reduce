#include <cassert>
#include <cstring>
#include <iostream>
#include <openssl/rand.h>
#include <ctime>
#include <vector>
#include <stdlib.h>
#include <math.h>
#include <unistd.h>
#include <fcntl.h>
#include <fstream>
#include <cstring>

#include "../common/contextmanager.h"
#include "../common/crypto.h"
#include "../common/file.h"
#include "../common/net.h"
#include "../common/protocol.h"

#include "requests.h"

using namespace std;

/// Pad a vec with random characters to get it to size sz
///
/// @param v  The vector to pad
/// @param sz The size that the vector should be **after** padding
///
/// @returns true if the padding was done, false on any error
bool padR(std::vector<uint8_t> &v) {
  if (v.size() >= LEN_RBLOCK_CONTENT) return false;
  else {
  //  uint8_t buf [LEN_RBLOCK_CONTENT]; 
   int num_of_pad = LEN_RBLOCK_CONTENT - v.size();
   uint8_t buf [num_of_pad];
   int status = RAND_bytes(buf, num_of_pad);
   v.insert(v.end(), buf,buf+sizeof(buf));
   if (status) return true; else return false;
  }
}

/// Pad a vec with random characters to get it to size sz
///
/// @param v  The vector to pad
/// @param sz The size that the vector should be **after** padding
///
/// @returns true if the padding was done, false on any error
bool pad0(std::vector<uint8_t> &v) {
  if(v.size() >= LEN_RKBLOCK) 
    return true;
  else {
    int num_of_pad = LEN_RKBLOCK - v.size();
    try {
      for (int i=0; i<num_of_pad; i++) {
        v.push_back('\0');  // convert 0-255 (chars) into vector v
      }
      return true;
    }
    catch (bad_alloc err){  // if reallocation failed to take place
      return false;
    }
  }
}

/// Check if the provided result vector is a string representation of ERR_CRYPTO
///
/// @param v The vector being compared to RES_ERR_CRYPTO
///
/// @returns true if the vector contents are RES_ERR_CRYPTO, false otherwise
bool check_err(const vector<uint8_t> &v)
{
  string err_exist (v.begin() ,v.begin() + 9);
  string err_no_data (v.begin() ,v.begin() + 11);
  string err_no_cryto (v.begin() ,v.begin() + 10);
  if (!err_exist.compare("ERR_LOGIN")) {
    cout <<RES_ERR_LOGIN;
    return true;
  } 
  else if (!err_no_data.compare("ERR_NO_DATA")) {
    cout<<RES_ERR_NO_DATA;
    return true;
  }
  else if (!err_no_data.compare("ERR_CRYPTO")) {
    cout<<RES_ERR_CRYPTO;
    return true;
  }return false;
}

vector<uint8_t> ablock_ss(const string &s1, const string &s2)
{
  string str =s1+s2;
  vector<uint8_t> v(str.begin(), str.end());
  return v;
}
vector<uint8_t> ablock_sss(const string &s1, const string &s2, const string &s3)
{
  string str =s1+s2+s3;
  vector<uint8_t> v(str.begin(), str.end());
  return v;
}

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

void print(const vector<uint8_t> &v) {
    for (const char &c: v) {
        std::cout << c;
    }
}

/// If a buffer consists of  ___OK___bbbbbbbbd+, where bbbbbbbb is a 8-byte binary integer
/// and d+ is a string of characters, write the bytes (d+) to a file
///
/// @param buf      The buffer holding a response
/// @param filename The name of the file to write
void send_result_to_file(const vector<uint8_t> &buf, const string &filename) {
  // cout <<"buf is "<<buf.data()<<'\n';
  // cout <<"filename is "<<filename<<'\n';
  string str_status (buf.begin(),buf.begin()+8);
  if (!str_status.compare("___OK___")) {
    vector<uint8_t> binary_vec (buf.begin()+8, buf.begin() + 16);
    // cout<<"Printing binary "<<binary_vec.size()<<'\n';
    size_t size_content = bin2dec(binary_vec);
    // cout<<"Size of rsa is "<<size_content<<'\n';
    vector<uint8_t> content (buf.begin()+16, (buf.begin() + 16+size_content));
    write_file(filename,content,0);
  }
}


/// Send a message to the server, using the common format for secure messages,
/// then take the response from the server, decrypt it, and return it.
///
/// Many of the messages in our server have a common form (@rblock.@ablock):
/// @rblock   enc(pubkey, padR("REGISTER".aeskey.len(@ablock)))
/// @ablock   enc(aeskey, len(@u).len(@p).null(8).null(8).@u.@p)
///
/// @param sd  An open socket
/// @param pub The server's public key, for encrypting the aes key
/// @param cmd The command that is being sent
/// @param msg The contents of the @ablock
///
/// @returns a vector with the (encrypted) result, or an empty vector on error
vector<uint8_t> send_cmd(int sd, RSA *pub, const string &cmd, const vector<uint8_t> &msg){
  auto aes_key = create_aes_key(); 
  EVP_CIPHER_CTX *ctx_enc = create_aes_context(aes_key,true);
  vector<uint8_t> enc_ablock = aes_crypt_msg(ctx_enc, msg);  //encrypted ablock

  
  vector<uint8_t> rsa_vec (cmd.begin(),cmd.end());  // @rblock's cmd
  rsa_vec.insert(rsa_vec.end(),aes_key.begin(),aes_key.end()); //@rblock's aes_key
  size_t size_of_ablock = enc_ablock.size(); 

  vector<uint8_t> binary_ablock = convert_len_to_hex(size_of_ablock); // populate binary representation in binary_ablock
  rsa_vec.insert(rsa_vec.end(),binary_ablock.begin(),binary_ablock.end()); // @rblock's binary presentation of size of ablock

  vector <uint8_t> enc_rblock (RSA_size(pub),0); 
  // vector <uint8_t> enc_rblock (RSA_size(pub),0); 
  vector <uint8_t> enc_client_block;
  if(padR(rsa_vec)) {
    RSA_public_encrypt(rsa_vec.size(),rsa_vec.data(),enc_rblock.data(),pub,RSA_PKCS1_OAEP_PADDING); // using RSA public encrpt from openssh
    
    enc_client_block.insert(enc_client_block.end(),enc_rblock.begin(),enc_rblock.end());
    enc_client_block.insert(enc_client_block.end(),enc_ablock.begin(),enc_ablock.end());
    vector<uint8_t> server_res_dec;
    if (send_reliably(sd,enc_client_block)) { //send block to server
      auto server_res_enc = reliable_get_to_eof (sd);   // recevive encrypted res from server
      reset_aes_context(ctx_enc,aes_key,false);
      server_res_dec = aes_crypt_msg(ctx_enc,server_res_enc);
      reclaim_aes_context(ctx_enc); // reclaim ctx context
      return server_res_dec;
    }
  } else return {}; // padR on error 
}

/// req_key() writes a request for the server's key on a socket descriptor.
/// When it gets a key back, it writes it to a file.
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param keyfile The name of the file to which the key should be written
void req_key(int sd, const string &keyfile) {
  // NB: These asserts are to prevent compiler warnings
  vector<uint8_t> req (REQ_KEY.begin(),REQ_KEY.end());
  pad0(req);
  if (send_reliably(sd,req)) {
    vector <uint8_t> res = reliable_get_to_eof(sd); 
    write_file(keyfile, res, 0);
  }  // send req to sd
  assert(sd);
  assert(keyfile.length() > 0);
}

/// req_reg() sends the REG command to register a new user
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
void req_reg(int sd, RSA *pubkey, const string &user, const string &pass,
             const string &, const string &) {
  if (user.length() <=LEN_UNAME && pass.length() <= LEN_PASSWORD) { // conform with protocal.h
    vector<uint8_t> user_bin = convert_len_to_hex(user.length());
    vector<uint8_t> pass_bin = convert_len_to_hex(pass.length());
    vector<uint8_t> msg (16,'\0');
    msg.insert(msg.begin(),pass_bin.begin(),pass_bin.end());
    msg.insert(msg.begin(),user_bin.begin(),user_bin.end());
    vector<uint8_t> user_info = ablock_ss(user,pass);
    msg.insert(msg.end(),user_info.begin(),user_info.end()); // vector msg was set up here
    //calling send_cmd() ...
    auto server_res_dec = send_cmd(sd,pubkey,REQ_REG,msg);
    print(server_res_dec);
  }
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(pubkey);
  assert(user.length() > 0);
  assert(pass.length() > 0);
}

/// req_bye() writes a request for the server to exit.
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
void req_bye(int sd, RSA *pubkey, const string &user, const string &pass,
             const string &, const string &) {
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(pubkey);
  assert(user.length() > 0);
  assert(pass.length() > 0);
  if (user.length() <=LEN_UNAME && pass.length() <= LEN_PASSWORD) { // conform with protocal.h
    vector<uint8_t> user_bin = convert_len_to_hex(user.length());
    vector<uint8_t> pass_bin = convert_len_to_hex(pass.length());
    vector<uint8_t> msg (16,'\0');
    msg.insert(msg.begin(),pass_bin.begin(),pass_bin.end());
    msg.insert(msg.begin(),user_bin.begin(),user_bin.end());
    vector<uint8_t> user_info = ablock_ss(user,pass);
    msg.insert(msg.end(),user_info.begin(),user_info.end()); // vector msg was set up here
    //calling send_cmd() ...
    auto server_res_dec = send_cmd(sd,pubkey,REQ_BYE,msg);
    print(server_res_dec);
  }
}

/// req_sav() writes a request for the server to save its contents
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
void req_sav(int sd, RSA *pubkey, const string &user, const string &pass,
             const string &, const string &) {
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(pubkey);
  assert(user.length() > 0);
  assert(pass.length() > 0);
  if (user.length() <=LEN_UNAME && pass.length() <= LEN_PASSWORD) { // conform with protocal.h
    vector<uint8_t> user_bin = convert_len_to_hex(user.length());
    vector<uint8_t> pass_bin = convert_len_to_hex(pass.length());
    vector<uint8_t> msg (16,'\0');
    msg.insert(msg.begin(),pass_bin.begin(),pass_bin.end());
    msg.insert(msg.begin(),user_bin.begin(),user_bin.end());
    vector<uint8_t> user_info = ablock_ss(user,pass);
    msg.insert(msg.end(),user_info.begin(),user_info.end()); // vector msg was set up here
    //calling send_cmd() ...
    auto server_res_dec = send_cmd(sd,pubkey,REQ_SAV,msg);
    print(server_res_dec);
  }
}

/// req_set() sends the SET command to set the content for a user
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
/// @param setfile The file whose contents should be sent
void req_set(int sd, RSA *pubkey, const string &user, const string &pass,
             const string &setfile, const string &) {
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(pubkey);
  assert(user.length() > 0);
  assert(pass.length() > 0);
  assert(setfile.length() > 0);
  // get all bytes defined by setfile
  auto file_content = load_entire_file(setfile);
  if (user.length() <=LEN_UNAME && pass.length() <= LEN_PASSWORD && file_content.size() <= LEN_PROFILE_FILE) { // conform with protocal.h
    auto file_bin = convert_len_to_hex(file_content.size());
    vector<uint8_t> user_bin = convert_len_to_hex(user.length());
    vector<uint8_t> pass_bin = convert_len_to_hex(pass.length());
    vector<uint8_t> msg (8,'\0');
    msg.insert(msg.begin(),file_bin.begin(),file_bin.end());
    msg.insert(msg.begin(),pass_bin.begin(),pass_bin.end());
    msg.insert(msg.begin(),user_bin.begin(),user_bin.end());
    vector<uint8_t> user_info = ablock_ss(user,pass);
    msg.insert(msg.end(),user_info.begin(),user_info.end()); 
    msg.insert(msg.end(),file_content.begin(),file_content.end());  // vector msg was set up here
    //calling send_cmd() ...
    auto server_res_dec = send_cmd(sd,pubkey,REQ_SET,msg);
    print(server_res_dec);
  }
}

/// req_get() requests the content associated with a user, and saves it to a
/// file called <user>.file.dat.
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
/// @param getname The name of the user whose content should be fetched
void req_get(int sd, RSA *pubkey, const string &user, const string &pass,
             const string &getname, const string &) {
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(pubkey);
  assert(user.length() > 0);
  assert(pass.length() > 0);
  assert(getname.length() > 0);
  if (user.length() <=LEN_UNAME && pass.length() <= LEN_PASSWORD && getname.length() <=LEN_UNAME) { // conform with protocal.h
    auto get_name_bin = convert_len_to_hex(getname.length());
    vector<uint8_t> user_bin = convert_len_to_hex(user.length());
    vector<uint8_t> pass_bin = convert_len_to_hex(pass.length());
    vector<uint8_t> msg (8,'\0');
    msg.insert(msg.begin(),get_name_bin.begin(),get_name_bin.end());
    msg.insert(msg.begin(),pass_bin.begin(),pass_bin.end());
    msg.insert(msg.begin(),user_bin.begin(),user_bin.end());
    vector<uint8_t> user_info = ablock_ss(user,pass);
    msg.insert(msg.end(),user_info.begin(),user_info.end()); 
    msg.insert(msg.end(),getname.begin(),getname.end());  // vector msg was set up here
    //calling send_cmd() ...
    auto server_res_dec = send_cmd(sd,pubkey,REQ_GET,msg);
    if(!check_err(server_res_dec)) {
      vector<uint8_t> status (server_res_dec.begin(),server_res_dec.begin()+8);
      send_result_to_file(server_res_dec,getname+".file.dat");
      cout<<status.data();
    }
  }
}

/// req_all() sends the ALL command to get a listing of all users, formatted
/// as text with one entry per line.
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
/// @param allfile The file where the result should go
void req_all(int sd, RSA *pubkey, const string &user, const string &pass,
             const string &allfile, const string &) {
  // cout << "requests.cc::req_all() is not implemented\n";
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(pubkey);
  assert(user.length() > 0);
  assert(pass.length() > 0);
  assert(allfile.length() > 0);
  if (user.length() <=LEN_UNAME && pass.length() <= LEN_PASSWORD ) { // conform with protocal.h
    vector<uint8_t> user_bin = convert_len_to_hex(user.length());
    vector<uint8_t> pass_bin = convert_len_to_hex(pass.length());
    vector<uint8_t> msg (16,'\0');
    msg.insert(msg.begin(),pass_bin.begin(),pass_bin.end());
    msg.insert(msg.begin(),user_bin.begin(),user_bin.end());
    vector<uint8_t> user_info = ablock_ss(user,pass);
    msg.insert(msg.end(),user_info.begin(),user_info.end()); // vector msg was set up here
    //calling send_cmd() ...
    auto server_res_dec = send_cmd(sd,pubkey,REQ_ALL,msg);
    if(!check_err(server_res_dec)) {
      vector<uint8_t> status (server_res_dec.begin(),server_res_dec.begin()+8);
      send_result_to_file(server_res_dec,allfile);
      cout<<status.data();
    }
  }
}
