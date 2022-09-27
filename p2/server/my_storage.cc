#include <cassert>
#include <cstring>
#include <functional>
#include <iostream>
#include <openssl/rand.h>
#include <string>
#include <vector>

#include "../common/contextmanager.h"
#include "../common/err.h"
#include "../common/protocol.h"

#include "authtableentry.h"
#include "format.h"
#include "map.h"
#include "map_factories.h"
#include "storage.h"

using namespace std;

/// MyStorage is the student implementation of the Storage class
class MyStorage : public Storage {
  /// The map of authentication information, indexed by username
  Map<string, AuthTableEntry> *auth_table;

  /// The map of key/value pairs
  Map<string, vector<uint8_t>> *kv_store;

  /// The name of the file from which the Storage object was loaded, and to
  /// which we persist the Storage object every time it changes
  string filename = "";

public:
  /// Construct an empty object and specify the file from which it should be
  /// loaded.  To avoid exceptions and errors in the constructor, the act of
  /// loading data is separate from construction.
  ///
  /// @param fname   The name of the file to use for persistence
  /// @param buckets The number of buckets in the hash table
  /// @param upq     The upload quota
  /// @param dnq     The download quota
  /// @param rqq     The request quota
  /// @param qd      The quota duration
  /// @param top     The size of the "top keys" cache
  /// @param admin   The administrator's username
  MyStorage(const std::string &fname, size_t buckets, size_t, size_t, size_t,
            double, size_t, const std::string &)
      : auth_table(authtable_factory(buckets)),
        kv_store(kvstore_factory(buckets)), filename(fname) {}

  /// Destructor for the storage object.
  virtual ~MyStorage() {}

  /// Create a new entry in the Auth table.  If the user already exists, return
  /// an error.  Otherwise, create a salt, hash the password, and then save an
  /// entry with the username, salt, hashed password, and a zero-byte content.
  ///
  /// @param user The user name to register
  /// @param pass The password to associate with that user name
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t add_user(const string &user, const string &pass) {
    // cout << "my_storage.cc::add_user() is not implemented\n";
    // // NB: These asserts are to prevent compiler warnings
    // assert(user.length() > 0);
    // assert(pass.length() > 0);
    // return {false, RES_ERR_UNIMPLEMENTED, {}};
    vector <uint8_t> salt (LEN_SALT,'0'), content;
    vector <uint8_t> vec_pass (pass.begin(),pass.end());
    // populate random byte into the salt 
    RAND_bytes(salt.data(), LEN_SALT);
    vec_pass.insert(vec_pass.end(),salt.begin(),salt.end());
    vector <uint8_t> hashed_pass (LEN_PASSHASH,'0');
    // hash the pass + salt with ctx
    SHA256_CTX ctx;
    SHA256_Init(&ctx);  //initialize ctx
    SHA256_Update(&ctx, vec_pass.data(), vec_pass.size());
    SHA256_Final(hashed_pass.data(), &ctx);
    AuthTableEntry entry {user, salt, hashed_pass, content};
    if(auth_table->insert(user, entry, [](){})) 
      return {true, RES_OK, {}};
    else return {false, RES_ERR_USER_EXISTS,{}};

  }

  /// Set the data bytes for a user, but do so if and only if the password
  /// matches
  ///
  /// @param user    The name of the user whose content is being set
  /// @param pass    The password for the user, used to authenticate
  /// @param content The data to set for this user
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t set_user_data(const string &user, const string &pass,
                                 const vector<uint8_t> &content) {
    // cout << "my_storage.cc::set_user_data() is not implemented\n";
    // // NB: These asserts are to prevent compiler warnings
    // assert(user.length() > 0);
    // assert(pass.length() > 0);
    // assert(content.size() > 0);
    // return {false, RES_ERR_UNIMPLEMENTED, {}};
    result_t res = auth(user,pass); 
    vector <uint8_t> salt, hashed_pass;
    if (res.succeeded) {
      auth_table->do_with_readonly(user, [&](AuthTableEntry e) {
        salt = e.salt;
        hashed_pass = e.pass_hash;
      });
      AuthTableEntry entry {user,salt,hashed_pass,content};
      auth_table->upsert(user,entry,[](){},[](){});
      return {true,RES_OK,{}};
    }
    else return {false,RES_ERR_LOGIN,{}};

  }

  /// Return a copy of the user data for a user, but do so only if the password
  /// matches
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param who  The name of the user whose content is being fetched
  ///
  /// @return A result tuple, as described in storage.h.  Note that "no data" is
  ///         an error
  virtual result_t get_user_data(const string &user, const string &pass,
                                 const string &who) {
    cout << "my_storage.cc::get_user_data() is not implemented\n";
    // NB: These asserts are to prevent compiler warnings
    assert(user.length() > 0);
    assert(pass.length() > 0);
    assert(who.length() > 0);
    return {false, RES_ERR_UNIMPLEMENTED, {}};
  }

  /// Return a newline-delimited string containing all of the usernames in the
  /// auth table
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t get_all_users(const string &user, const string &pass) {
    cout << "my_storage.cc::get_all_users() is not implemented\n";
    // NB: These asserts are to prevent compiler warnings
    assert(user.length() > 0);
    assert(pass.length() > 0);
    return {false, RES_ERR_UNIMPLEMENTED, {}};
  }

  /// Authenticate a user
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t auth(const string &user, const string &pass) {
    // cout << "my_storage.cc::auth() is not implemented\n";
    // return {false, RES_ERR_UNIMPLEMENTED, {}};
    vector <uint8_t> usr_salt, usr_hashed_pass;
    if (!auth_table->do_with_readonly(user,[&](AuthTableEntry e){
      usr_salt = e.salt; usr_hashed_pass = e.pass_hash;
    })) return {false, RES_ERR_LOGIN, {}};
    // obtain pass in plain text 
    vector <uint8_t> vec_pass (pass.begin(),pass.end());  
    vec_pass.insert(vec_pass.end(), usr_salt.begin(),usr_salt.end());
    vector <uint8_t> hashed_pass (LEN_PASSHASH); // initialize a fixed sized
    // hash the pass + salt with ctx
    SHA256_CTX ctx;
    SHA256_Init(&ctx);  //initialize ctx
    SHA256_Update(&ctx, vec_pass.data(), vec_pass.size());
    SHA256_Final(hashed_pass.data(), &ctx);
    // compare and return 
    if (hashed_pass != usr_hashed_pass) 
      return {false, RES_ERR_LOGIN, {}};
    else return {true, RES_OK, {}};
  }

  /// Create a new key/value mapping in the table
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose mapping is being created
  /// @param val  The value to copy into the map
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_insert(const string &user, const string &pass,
                             const string &key, const vector<uint8_t> &val) {
    // cout << "my_storage.cc::kv_insert() is not implemented\n";
    // // NB: These asserts are to prevent compiler warnings
    // assert(user.length() > 0);
    // assert(pass.length() > 0);
    // assert(key.length() > 0);
    // assert(val.size() > 0);
    // return {false, RES_ERR_UNIMPLEMENTED, {}};
    auto res = auth(user, pass);
    if (!res.succeeded) return {false,res.msg,{}};
    if(!(kv_store->insert(key, vector(val), [](){})))
      return{false,RES_ERR_KEY,{}};
    return {true, RES_OK, {}};
  };

  /// Get a copy of the value to which a key is mapped
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose value is being fetched
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_get(const string &user, const string &pass,
                          const string &key) {
    // cout << "my_storage.cc::kv_get() is not implemented\n";
    // // NB: These asserts are to prevent compiler warnings
    // assert(user.length() > 0);
    // assert(pass.length() > 0);
    // assert(key.length() > 0);
    // return {false, RES_ERR_UNIMPLEMENTED, {}};
    auto res = auth(user,pass);
    if(!res.succeeded) return {false,res.msg,{}};
    vector <uint8_t> content;
    if (kv_store->do_with_readonly(key,[&](const vector <uint8_t> &value){
      content.insert(content.end(),value.begin(),value.end());
    })) return {true, RES_OK, content};
    else return {false, RES_ERR_KEY,{}};
  };

  /// Delete a key/value mapping
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose value is being deleted
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_delete(const string &user, const string &pass,
                             const string &key) {
    // cout << "my_storage.cc::kv_delete() is not implemented\n";
    // // NB: These asserts are to prevent compiler warnings
    // assert(user.length() > 0);
    // assert(pass.length() > 0);
    // assert(key.length() > 0);
    // return {false, RES_ERR_UNIMPLEMENTED, {}};
    auto res = auth(user,pass);
    if(!res.succeeded) return {false,res.msg,{}};
    if (kv_store->remove(key,[](){})) return {true, RES_OK, {}};
    else return {false, RES_ERR_KEY,{}}; 
  };

  /// Insert or update, so that the given key is mapped to the give value
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose mapping is being upserted
  /// @param val  The value to copy into the map
  ///
  /// @return A result tuple, as described in storage.h.  Note that there are
  ///         two "OK" messages, depending on whether we get an insert or an
  ///         update.
  virtual result_t kv_upsert(const string &user, const string &pass,
                             const string &key, const vector<uint8_t> &val) {
    // cout << "my_storage.cc::kv_upsert() is not implemented\n";
    // // NB: These asserts are to prevent compiler warnings
    // assert(user.length() > 0);
    // assert(pass.length() > 0);
    // assert(key.length() > 0);
    // assert(val.size() > 0);
    // return {false, RES_ERR_UNIMPLEMENTED, {}};
    auto res = auth(user,pass);
    if(!res.succeeded) return {false,res.msg,{}};
    if(kv_store->upsert(key,val,[](){},[](){})) 
      return {true,RES_OKINS,{}};
    return {true,RES_OKUPD,{}};
  };

  /// Return all of the keys in the kv_store, as a "\n"-delimited string
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_all(const string &user, const string &pass) {
    // cout << "my_storage.cc::kv_all() is not implemented\n";
    // NB: These asserts are to prevent compiler warnings
    // assert(user.length() > 0);
    // assert(pass.length() > 0);
    // return {false, RES_ERR_UNIMPLEMENTED, {}};
    auto res = auth(user,pass);
    if(!res.succeeded) return {false,res.msg,{}};
    vector <uint8_t> key_list;
    string keys;
    auto dummy = [](){};
    kv_store->do_all_readonly([&](string key, const vector <uint8_t> &){
      key += '\n';
      keys += key;
    },dummy);
    key_list.insert(key_list.end(),keys.begin(),keys.end());
    if (key_list.size() >0)
      return {true, RES_OK, key_list};
    return {false,RES_ERR_NO_DATA,{}};
  };

  /// Shut down the storage when the server stops.  This method needs to close
  /// any open files related to incremental persistence.  It also needs to clean
  /// up any state related to .so files.  This is only called when all threads
  /// have stopped accessing the Storage object.
  virtual void shutdown() {
    // cout << "my_storage.cc::shutdown() is not implemented\n";
  }

  /// Write the entire Storage object to the file specified by this.filename. To
  /// ensure durability, Storage must be persisted in two steps.  First, it must
  /// be written to a temporary file (this.filename.tmp).  Then the temporary
  /// file can be renamed to replace the older version of the Storage object.
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t save_file() {
    // cout << "my_storage.cc::save_file() is not implemented\n";
    // return {false, RES_ERR_UNIMPLEMENTED, {}};
    string new_file = this->filename;
    new_file += ".temp";
    FILE *fd = fopen(&new_file[0], "w+");

    // MODIFICATION HERE    (A chain of lambda)
    auto kv_lambda = [&] () {
      // write KV Table next
      kv_store->do_all_readonly([&](const string s, const vector<uint8_t> val){
        size_t byte_write =0;
        byte_write += fwrite(&KVENTRY[0],1,8,fd); //write flag
        size_t usr_len = s.length();
        byte_write += fwrite(&usr_len,1,8,fd);  //write username length 
        size_t val_len = val.size();
        byte_write += fwrite(&val_len,1,8,fd);  //write value length 
        byte_write += fwrite(&s[0], 1, usr_len,fd);
        byte_write += fwrite(val.data(), 1, val_len,fd);
        //byte_write += count;

        if ((byte_write %8) != 0) {
          //size_t num_zeros = 8 -(byte_write %8);
          size_t zero = 0;
          byte_write += fwrite(&zero, sizeof(char), 8 -(byte_write %8), fd);
          //cout<<"Second"<<byte_write;
        }
      },[](){});
    };

    // write Auth Table first
    auth_table->do_all_readonly([&](const string s, const AuthTableEntry e){
      size_t byte_write =0;
      byte_write += fwrite(&AUTHENTRY[0],1,8,fd); //write flag
      size_t usr_len = e.username.length();
      byte_write += fwrite(&usr_len,1,8,fd);  //write username length 
      size_t salt_len = e.salt.size();
      byte_write += fwrite(&salt_len,1,8,fd);  //write salt length 
      size_t pass_len = e.pass_hash.size();
      byte_write += fwrite(&pass_len,1,8,fd);  //write hasspass length 
      size_t prof_len = e.content.size();
      byte_write += fwrite(&prof_len,1,8,fd);  //write profile length 
      byte_write += fwrite(&s[0], 1, usr_len,fd);
      byte_write += fwrite(e.salt.data(), 1, salt_len,fd);
      byte_write += fwrite(e.pass_hash.data(), 1, pass_len,fd);
      if (prof_len) {  // profile not empty 
        byte_write += fwrite(e.content.data(), 1, prof_len,fd);
      }
      // cout<<"Second"<<byte_write;
      //byte_write +=  count;

      if ((byte_write %8) != 0) {
        size_t zero = 0;
        byte_write += fwrite(&zero, sizeof(char), 8 -(byte_write %8), fd);
        
      }
    },kv_lambda);

    // // write KV Table next
    // kv_store->do_all_readonly([&](const string s, const vector<uint8_t> val){
    //   size_t byte_write =0;
    //   byte_write += fwrite(&KVENTRY[0],1,8,fd); //write flag
    //   size_t usr_len = s.length();
    //   byte_write += fwrite(&usr_len,1,8,fd);  //write username length 
    //   size_t val_len = val.size();
    //   byte_write += fwrite(&val_len,1,8,fd);  //write value length 
    //   byte_write += fwrite(&s[0], 1, usr_len,fd);
    //   byte_write += fwrite(val.data(), 1, val_len,fd);
    //   //byte_write += count;

    //   if ((byte_write %8) != 0) {
    //     //size_t num_zeros = 8 -(byte_write %8);
    //     size_t zero = 0;
    //     byte_write += fwrite(&zero, sizeof(char), 8 -(byte_write %8), fd);
    //     //cout<<"Second"<<byte_write;
    //   }
    // },[](){});

    // rename the new file
    rename(&new_file[0],"company.dir");
    fclose(fd);
    return{true, RES_OK, {}};
  }

  /// Populate the Storage object by loading this.filename.  Note that load()
  /// begins by clearing the maps, so that when the call is complete, exactly
  /// and only the contents of the file are in the Storage object.
  ///
  /// @return A result tuple, as described in storage.h.  Note that a
  ///         non-existent file is not an error.
  virtual result_t load_file() {
    FILE *storage_file = fopen(filename.c_str(), "r");
    if (storage_file == nullptr) {
      return {true, "File not found: " + filename, {}};
    }
    vector<uint8_t> buf (8);
    
    while (fread(buf.data(), 1, 8, storage_file) ==8) {  // read until eof
      // convert buf to flags
      string read_flags(buf.begin(),buf.end());
      // Reading from authTable
      if (!read_flags.compare(AUTHENTRY)) {
        size_t read = 8;   // bytes already read
        //size_t count=0;  //num of 8 bytes 
        size_t usr_len, salt_len, hashed_pass_len, prof_len;
        read += fread(&usr_len,1,8,storage_file);
        read += fread(&salt_len,1,8,storage_file);
        read += fread(&hashed_pass_len,1,8,storage_file);
        read += fread(&prof_len,1,8,storage_file);
        //read += (count * 8);
        string user (usr_len,'\0');
        vector<uint8_t> salt(salt_len), hashed_pass(hashed_pass_len), profile(prof_len);
        read += fread(&user[0],1,usr_len,storage_file);
        // user += '\0';
        read += fread(salt.data(),1,salt_len,storage_file);
        read += fread(hashed_pass.data(),1,hashed_pass_len,storage_file);
        if (prof_len) {
          read += fread(profile.data(),1,prof_len,storage_file);
        }

        // deal with padding to align with 8 bytes 
        if ((read%8) != 0) {
          size_t dummpy_pad=0;
          read += fread(&dummpy_pad,sizeof(char),8- (read%8),storage_file);
          //cout<<"Third"<<read;
        }
        AuthTableEntry e {user, salt, hashed_pass, profile};
        auth_table ->insert(user, e, [](){});
      }
      // Reading from kv store
      else if (!read_flags.compare(KVENTRY)) {
        size_t read =8;  // already read 8 bytes
        size_t key_len, val_len;
        read += fread(&key_len,1,8,storage_file);
        read += fread(&val_len,1,8,storage_file);
        string key(key_len,'\0');
        read += fread(&key[0], 1,key_len, storage_file);
        // key += '\0';
        vector<uint8_t> val (val_len, '\0');
        read += fread(val.data(), 1,val_len, storage_file); 

        // deal with padding to align with 8 bytes 
        if ((read%8) != 0) {
          size_t dummpy_pad=0;
          read += fread(&dummpy_pad,sizeof(char),8- (read%8),storage_file);
          //cout<<"Forth"<<read;
        }
        kv_store->insert(key,val,[](){});
      }
    }
    fclose(storage_file);
    return {true, "Loaded: "+filename, {}};
  };
};

/// Create an empty Storage object and specify the file from which it should
/// be loaded.  To avoid exceptions and errors in the constructor, the act of
/// loading data is separate from construction.
///
/// @param fname   The name of the file to use for persistence
/// @param buckets The number of buckets in the hash table
/// @param upq     The upload quota
/// @param dnq     The download quota
/// @param rqq     The request quota
/// @param qd      The quota duration
/// @param top     The size of the "top keys" cache
/// @param admin   The administrator's username
Storage *storage_factory(const std::string &fname, size_t buckets, size_t upq,
                         size_t dnq, size_t rqq, double qd, size_t top,
                         const std::string &admin) {
  return new MyStorage(fname, buckets, upq, dnq, rqq, qd, top, admin);
}
