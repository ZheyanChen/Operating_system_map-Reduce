#include <cassert>
#include <cstdio>
#include <cstring>
#include <functional>
#include <iostream>
#include <memory>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>
#include <mutex>

#include "../common/contextmanager.h"
#include "../common/err.h"
#include "../common/protocol.h"

#include "authtableentry.h"
#include "format.h"
#include "helpers.h"
#include "map.h"
#include "map_factories.h"
#include "mru.h"
#include "persist.h"
#include "quotas.h"
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

  /// The open file
  FILE *storage_file = nullptr;

  mutex file_mtx;  // file mutex

  /// The upload quota
  const size_t up_quota;

  /// The download quota
  const size_t down_quota;

  /// The requests quota
  const size_t req_quota;

  /// The number of seconds over which quotas are enforced
  const double quota_dur;

  /// The table for tracking the most recently used keys
  mru_manager *mru;

  /// A table for tracking quotas
  Map<string, Quotas *> *quota_table;

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
  MyStorage(const std::string &fname, size_t buckets, size_t upq, size_t dnq,
            size_t rqq, double qd, size_t top, const std::string &)
      : auth_table(authtable_factory(buckets)),
        kv_store(kvstore_factory(buckets)), filename(fname), up_quota(upq),
        down_quota(dnq), req_quota(rqq), quota_dur(qd), mru(mru_factory(top)),
        quota_table(quotatable_factory(buckets)) {}

  /// Destructor for the storage object.
  virtual ~MyStorage() {
    // TODO: you probably want to free some memory here...
    delete auth_table;
    delete kv_store;
    delete quota_table;
    delete mru;
  }

  /// Create a new entry in the Auth table.  If the user already exists, return
  /// an error.  Otherwise, create a salt, hash the password, and then save an
  /// entry with the username, salt, hashed password, and a zero-byte content.
  ///
  /// @param user The user name to register
  /// @param pass The password to associate with that user name
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t add_user(const string &user, const string &pass) {
    // NB: the helper (.o provided) does all the work for this operation :)
    // Quotas* newquota;
    result_t res = add_user_helper(user, pass, auth_table, storage_file);
    if (res.succeeded) { 
      // create user_quotas on heap
      Quotas *user_quotas = new Quotas;
      user_quotas->uploads = quota_factory(up_quota,quota_dur);
      user_quotas->downloads = quota_factory(down_quota,quota_dur);
      user_quotas->requests = quota_factory(req_quota,quota_dur);
      // insert user_quotas into quota table
      quota_table->insert(user,user_quotas,[](){});
    }
    return res;
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
    // NB: the helper (.o provided) does all the work for this operation :)
    return set_user_data_helper(user, pass, content, auth_table, storage_file);
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
    // NB: the helper (.o provided) does all the work for this operation :)
    return get_user_data_helper(user, pass, who, auth_table);
  }

  /// Return a newline-delimited string containing all of the usernames in the
  /// auth table
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t get_all_users(const string &user, const string &pass) {
    // NB: the helper (.o provided) does all the work for this operation :)
    return get_all_users_helper(user, pass, auth_table);
  }

  /// Authenticate a user
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t auth(const string &user, const string &pass) {
    // NB: the helper (.o provided) does all the work for this operation :)
    return auth_helper(user, pass, auth_table);
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
     auto res = auth(user, pass);
    if (!res.succeeded) return {false,res.msg,{}};
    //NEW4 |||||||||||||||||
    bool uploadexceed =false;
    bool reqexceed =false;
    size_t sizeupload = val.size();
    quota_table->do_with(user,[&](auto &value){
      if(!(value->uploads->check_add(sizeupload)))
      {
        uploadexceed = true;
      }
      if (!(value->requests->check_add(1)))
      {
        reqexceed = true;
      }
    });
    if (reqexceed)
    {
      return {false, RES_ERR_QUOTA_REQ, {}};
    }
    if(uploadexceed)
    {
      return {false, RES_ERR_QUOTA_UP, {}};
    }
    
    //NEW4||||||||||||||||||
    auto lambda = [&] () {
      lock_guard<mutex> lock(file_mtx);
      mru->insert(key);//NEW4
      size_t byte_write =0;
      byte_write += fwrite(&KVENTRY[0],1,8,storage_file); //write flag
      size_t key_len = key.length();
      byte_write += fwrite(&key_len,1,8,storage_file);  //write username length 
      size_t val_len = val.size();
      byte_write += fwrite(&val_len,1,8,storage_file);  //write value length 
      byte_write += fwrite(key.data(), 1, key_len,storage_file);
      byte_write += fwrite(val.data(), 1, val_len,storage_file);
      if ((byte_write %8) != 0) {
        size_t zero = 0;
        byte_write += fwrite(&zero, sizeof(char), 8 -(byte_write %8), storage_file);
      }
    };
    {     
      if(!(kv_store->insert(key, vector(val), lambda)))
      {
        return{false,RES_ERR_KEY,{}};
      }
    }
    fflush(storage_file);
    fsync(fileno(storage_file));
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
    bool errkey=false;                       
    auto res = auth(user,pass);
    if(!res.succeeded) return {false,res.msg,{}};
    vector <uint8_t> content;
    if (!(kv_store->do_with_readonly(key,[&](const vector <uint8_t> &value){
      content.insert(content.end(),value.begin(),value.end());
    }))) 
    {
      errkey = true;
      
    }
    //NEW4||||| structure is slighly modified and tested
    bool downloadexceed =false;
    bool reqexceed =false;
    size_t sizedownload = content.size();
    quota_table->do_with(user,[&](auto &value){
      if(!(value->downloads->check_add(sizedownload)))
      {
        downloadexceed = true;
      }
      if (!(value->requests->check_add(1)))
      {
        reqexceed = true;
      }
    });
    if (reqexceed)
    {
      return {false, RES_ERR_QUOTA_REQ, {}};
    }
    if(downloadexceed)
    {
      return {false, RES_ERR_QUOTA_DOWN, {}};
    }
    
    //NEW4|||||
    if (errkey == true)
    {
      return {false, RES_ERR_KEY,{}};
    } 
    mru->insert(key);//NEW4
    return {true, RES_OK, content};
    
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
    auto res = auth(user,pass);
    if(!res.succeeded) return {false,res.msg,{}};
    //NEW
    //NEW4||||| structure is slighly modified and tested
    bool reqexceed =false;
    quota_table->do_with(user,[&](auto &value){
      if (!(value->requests->check_add(1))){
        reqexceed = true;
      }
    });
    if (reqexceed){
      return {false, RES_ERR_QUOTA_REQ, {}};
    }
    //NEW4|||||
    auto lambda = [&]() {
      mru->remove(key);//NEW4
      lock_guard<mutex> lock(file_mtx);
      size_t byte_write =0;
      byte_write += fwrite(&KVDELETE[0],1,8,storage_file); //write flag
      size_t key_len = key.length();
      byte_write += fwrite(&key_len,1,8,storage_file);  //write username length 
      byte_write += fwrite(key.data(), 1, key_len,storage_file);
      if ((byte_write %8) != 0) {
        size_t zero = 0;
        byte_write += fwrite(&zero, sizeof(char), 8 -(byte_write %8), storage_file);
      }
    };
    
    if (kv_store->remove(key,lambda)) {
      fflush(storage_file);
      fsync(fileno(storage_file));
      return {true, RES_OK, {}};
    }
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
  /// two
  ///         "OK" messages, depending on whether we get an insert or an update.
  virtual result_t kv_upsert(const string &user, const string &pass,
                             const string &key, const vector<uint8_t> &val) {
    auto res = auth(user,pass);
    if(!res.succeeded) return {false,res.msg,{}};
    //NEW4||||| structure is slighly modified and tested
    bool uploadexceed =false;
    bool reqexceed =false;
    size_t sizeupload = val.size();
    quota_table->do_with(user,[&](auto &value){
      if(!(value->uploads->check_add(sizeupload)))
      {
        uploadexceed = true;
      }
      if (!(value->requests->check_add(1)))
      {
        reqexceed = true;
      }
    });
    if (reqexceed)
    {
      return {false, RES_ERR_QUOTA_REQ, {}};
    }
    if(uploadexceed)
    {
      return {false, RES_ERR_QUOTA_UP, {}};
    }
    
    //NEW4|||||
    auto ins_lam = [&] () {
      mru->insert(key);//NEW4
      lock_guard<mutex> lock(file_mtx);
      size_t byte_write =0;
      byte_write += fwrite(&KVENTRY[0],1,8,storage_file); //write flag
      size_t key_len = key.length();
      byte_write += fwrite(&key_len,1,8,storage_file);  //write username length 
      size_t val_len = val.size();
      byte_write += fwrite(&val_len,1,8,storage_file);  //write value length 
      byte_write += fwrite(key.data(), 1, key_len,storage_file);
      byte_write += fwrite(val.data(), 1, val_len,storage_file);
      if ((byte_write %8) != 0) {
        size_t zero = 0;
        byte_write += fwrite(&zero, sizeof(char), 8 -(byte_write %8), storage_file);
      }
      fflush(storage_file);
      fsync(fileno(storage_file));
    };

    auto upd_lam = [&] () {
      mru->insert(key);//NEW4
      lock_guard<mutex> lock(file_mtx);
      size_t byte_write =0;
      byte_write += fwrite(&KVUPDATE[0],1,8,storage_file); //write flag
      size_t key_len = key.length();
      byte_write += fwrite(&key_len,1,8,storage_file);  //write username length 
      size_t val_len = val.size();
      byte_write += fwrite(&val_len,1,8,storage_file);  //write value length 
      byte_write += fwrite(key.data(), 1, key_len,storage_file);
      byte_write += fwrite(val.data(), 1, val_len,storage_file);
      if ((byte_write %8) != 0) {
        size_t zero = 0;
        byte_write += fwrite(&zero, sizeof(char), 8 -(byte_write %8), storage_file);
      }
      fflush(storage_file);
      fsync(fileno(storage_file));
    };
    

    if(kv_store->upsert(key,val,ins_lam,upd_lam))
    {    // KV_UPSERT insert Branch
      return {true,RES_OKINS,{}}; 
    } 
    else { // KV_UPSERT upsert Branch
      return {true,RES_OKUPD,{}};
    }
  };

  /// Return all of the keys in the kv_store, as a "\n"-delimited string
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_all(const string &user, const string &pass) {
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
    if (key_list.size() <=0)
    {
      return {false,RES_ERR_NO_DATA,{}};
    }
    //NEW4||||| structure is slighly modified and tested
    bool downloadexceed =false;
    bool reqexceed =false;
    size_t sizedownload = key_list.size();
    quota_table->do_with(user,[&](auto &value){
      if(!(value->downloads->check_add(sizedownload)))
      {
        downloadexceed = true;
      }
      if (!(value->requests->check_add(1)))
      {
        reqexceed = true;
      }
    });
    if (reqexceed)
    {
      return {false, RES_ERR_QUOTA_REQ, {}};
    }
    if(downloadexceed)
    {
      return {false, RES_ERR_QUOTA_DOWN, {}};
    }  
    //NEW4|||||
    return {true, RES_OK, key_list};
  };

  /// Return all of the keys in the kv_store's MRU cache, as a "\n"-delimited
  /// string
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_top(const string &user, const string &pass) {
    auto res = auth(user,pass);
    if(!res.succeeded) return {false,res.msg,{}};
    // NB: These asserts are to prevent compiler warnings.. you can delete them
    //     when you implement this method
    string rv = mru->get();//NEW4
    //string rv;
    vector<uint8_t> content(rv.begin(), rv.end());//NEW4
    //NEW4|||||||||
    bool downloadexceed =false;
    bool reqexceed =false;
    size_t sizedownload = content.size();
    quota_table->do_with(user,[&](auto &value){
      if(!(value->downloads->check_add(sizedownload)))
      {
        downloadexceed = true;
      }
      if (!(value->requests->check_add(1)))
      {
        reqexceed = true;
      }
    });
    if (reqexceed)
    {
      return {false, RES_ERR_QUOTA_REQ, {}};
    }
    if(downloadexceed)
    {
      return {false, RES_ERR_QUOTA_DOWN, {}};
    }
    if (content.size()==0)
    {
      return {false, RES_ERR_NO_DATA,content};
    }
    //NEW4|||||||||
    return {true, RES_OK, content};//TBD
  };

  /// Shut down the storage when the server stops.  This method needs to close
  /// any open files related to incremental persistence.  It also needs to clean
  /// up any state related to .so files.  This is only called when all threads
  /// have stopped accessing the Storage object.
  virtual void shutdown() {
    // NB: Based on how the other methods are implemented in the helper file, we
    //     need this command here:
    //mru->clear();//NEW4
    fclose(storage_file);
  }

  /// Write the entire Storage object to the file specified by this.filename. To
  /// ensure durability, Storage must be persisted in two steps.  First, it must
  /// be written to a temporary file (this.filename.tmp).  Then the temporary
  /// file can be renamed to replace the older version of the Storage object.
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t save_file() {
    // NB: the helper (.o provided) does all the work for this operation :)
    return save_file_helper(auth_table, kv_store, filename, storage_file);
  }

  /// Populate the Storage object by loading this.filename.  Note that load()
  /// begins by clearing the maps, so that when the call is complete, exactly
  /// and only the contents of the file are in the Storage object.
  ///
  /// @return A result tuple, as described in storage.h.  Note that a
  /// non-existent
  ///         file is not an error.
  virtual result_t load_file() {
    // NB: the helper (.o provided) does all the work from p1/p2/p3 for this
    //     operation.  Depending on how you choose to implement quotas, you may
    //     need to edit this.
    return load_file_helper(auth_table, kv_store, filename, storage_file);
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
