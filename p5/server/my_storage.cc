#include <cassert>
#include <functional>
#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <vector>

#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/wait.h>

#include "../common/contextmanager.h"
#include "../common/protocol.h"

#include "functable.h"
#include "helpers.h"
#include "map.h"
#include "map_factories.h"
#include "mru.h"
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

  /// The name of the admin user
  string admin_name;

  /// The function table, to support executing map/reduce on the kv_store
  FuncTable *funcs;

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
            size_t rqq, double qd, size_t top, const std::string &admin)
      : auth_table(authtable_factory(buckets)),
        kv_store(kvstore_factory(buckets)), filename(fname), up_quota(upq),
        down_quota(dnq), req_quota(rqq), quota_dur(qd), mru(mru_factory(top)),
        quota_table(quotatable_factory(buckets)), admin_name(admin),
        funcs(functable_factory()) {}

  /// Destructor for the storage object.
  virtual ~MyStorage() {
    delete auth_table;
    delete kv_store;
    delete mru;
    delete quota_table;
    delete funcs;
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
    return add_user_helper(user, pass, auth_table, storage_file);
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
    return get_all_users_helper(user, pass, auth_table);
  }

  /// Authenticate a user
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t auth(const string &user, const string &pass) {
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
    return kv_insert_helper(user, pass, key, val, auth_table, kv_store,
                            storage_file, mru, up_quota, down_quota, req_quota,
                            quota_dur, quota_table);
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
    return kv_get_helper(user, pass, key, auth_table, kv_store, mru, up_quota,
                         down_quota, req_quota, quota_dur, quota_table);
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
    return kv_delete_helper(user, pass, key, auth_table, kv_store, storage_file,
                            mru, up_quota, down_quota, req_quota, quota_dur,
                            quota_table);
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
    return kv_upsert_helper(user, pass, key, val, auth_table, kv_store,
                            storage_file, mru, up_quota, down_quota, req_quota,
                            quota_dur, quota_table);
  };

  /// Return all of the keys in the kv_store, as a "\n"-delimited string
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_all(const string &user, const string &pass) {
    return kv_all_helper(user, pass, auth_table, kv_store, up_quota, down_quota,
                         req_quota, quota_dur, quota_table);
  };

  /// Return all of the keys in the kv_store's MRU cache, as a "\n"-delimited
  /// string
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_top(const string &user, const string &pass) {
    return kv_top_helper(user, pass, auth_table, mru, up_quota, down_quota,
                         req_quota, quota_dur, quota_table);
  };

  /// Register a .so with the function table
  ///
  /// @param user   The name of the user who made the request
  /// @param pass   The password for the user, used to authenticate
  /// @param mrname The name to use for the registration
  /// @param so     The .so file contents to register
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t register_mr(const string &user, const string &pass,
                               const string &mrname,
                               const vector<uint8_t> &so) {
    auto res = auth(user,pass);
    if (!res.succeeded) 
      return {false, res.msg,{}};
    if(user != admin_name)
    {
      return {false,RES_ERR_LOGIN,{}};
    }
    else {
      string reg_mr_status = funcs->register_mr(mrname,so);
      if (reg_mr_status == RES_OK) return {true,RES_OK,{}};
      else return {false,reg_mr_status,{}};
    }
  };

  /// Run a map/reduce on all the key/value tuples of the kv_store
  ///
  /// @param user   The name of the user who made the request
  /// @param pass   The password for the user, to authenticate
  /// @param mrname The name of the map/reduce functions to use
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t invoke_mr(const string &user, const string &pass,
                             const string &mrname) {
    result_t res = auth(user,pass);
    if(!res.succeeded)
      return {false,res.msg,{}};
    
    //////////// NEW FORK CODE //////////////
    int fd1[2], fd2[2], n_bytes, pid;
    char first_8_bytes[8];  // 1st 8 bytes store the tot length of kv_vec
    if (pipe(fd1) < 0 || pipe(fd2) < 0) {
      perror("pipe");
      exit(1);
    }
    if ((pid = fork()) == 0) { //child process
      close(fd1[1]);
      close(fd2[0]);
      prctl(PR_SET_SECCOMP,SECCOMP_MODE_STRICT);  // set strict seccomp mode
      vector<vector<uint8_t>> vec_of_map_res;

      // set up all the so functions
      pair <map_func,reduce_func> mr_pair = funcs->get_mr(mrname);
      map_func map = mr_pair.first;
      reduce_func reduce = mr_pair.second;

      // child continuously read from pipe 
      // read might suspend child processs 
      while ((n_bytes = read (fd1[0],first_8_bytes,sizeof(first_8_bytes))) > 0) {
        // fetching key && val
        size_t tot_vec_len;
        memcpy(&tot_vec_len,&first_8_bytes,8);   //convert an array of size 8 to size_t
        vector <uint8_t> kv_str (tot_vec_len,'\0');               // store the rest of bytes of the pipe
        n_bytes = read(fd1[0],kv_str.data(),tot_vec_len);
        vector <uint8_t> keylen_vec (kv_str.begin(),kv_str.begin()+8);     // slice kv_vec to get keylen
        size_t key_len;
        memcpy(&key_len,keylen_vec.data(),8);            // covert str to size_t
        string key (kv_str.begin()+8,kv_str.begin()+8+key_len);  // fetch key from kv_vec
        vector <uint8_t> vallen_vec (kv_str.begin()+8+key_len,kv_str.begin()+8+key_len+8);     // slice kv_vec to get keylen
        size_t val_len;
        memcpy(&val_len,vallen_vec.data(),8);            // covert str to size_t
        vector <uint8_t> val (kv_str.begin()+8+key_len+8, kv_str.begin()+8+key_len+8+val_len); // fetch key from kv_vec
        vector<uint8_t> map_res = map(key,val);
        vec_of_map_res.push_back(map_res);
      }
      
      // do the reduce when there is no first 8 bytes in the pipe 
      /*
        protocol of reduce_res is "reducelen.reduce_res"
      */
      vector <uint8_t> reduce_res = reduce(vec_of_map_res);
      size_t reduce_res_size = reduce_res.size();
      vector<uint8_t> res_vec (8,'\0');
      memcpy(res_vec.data(),&reduce_res_size,8);
      res_vec.insert(res_vec.end(),reduce_res.begin(),reduce_res.end());

      // write back to parent process
      n_bytes = write(fd2[1],res_vec.data(), res_vec.size());  // using the fd2
      close (fd2[1]); 
      close(fd1[0]);  
      exit(EXIT_SUCCESS);       // child process exit normally
    }
    else { //parent process 
      int status;
      close(fd1[0]);
      close(fd2[1]);
      auto then_lambda = [&] () {}; 
      kv_store->do_all_readonly([&] (auto key, auto val){  
        /*
          the protocol is 
            "totlen.keylen.key.vallen.val"
        */
        size_t key_len = key.size();
        size_t val_len = val.size();
        vector <uint8_t> key_vec (8,'\0');
        memcpy(key_vec.data(),&key_len,8);   // 8 bytes key length
        key_vec.insert(key_vec.end(),key.begin(),key.end());
        vector <uint8_t> val_vec (8,'\0');
        memcpy(val_vec.data(),&val_len,8);   // 8 bytes val length
        val_vec.insert(val_vec.end(),val.begin(),val.end());
        vector <uint8_t> kv_vec (key_vec.begin(),key_vec.end());
        kv_vec.insert(kv_vec.end(),val_vec.begin(),val_vec.end()); 
        vector <uint8_t> tot_vec (8,'\0');
        size_t tot_size = kv_vec.size();
        memcpy(tot_vec.data(),&tot_size,8);   // 8 bytes kv_vec length
        kv_vec.insert(kv_vec.begin(),tot_vec.begin(),tot_vec.end());
        // write to fd1 
        n_bytes = write (fd1[1],kv_vec.data(),kv_vec.size());  
        
      },then_lambda);
      close(fd1[1]);
        // parent check status and handle error
      //if (WIFEXITED(status) != 0) {  //child exits normally read fd2
      n_bytes = read(fd2[0],first_8_bytes,8);  // read first 8 bytes to get the actual size
      if(n_bytes<=0)
      {
        return {false, RES_ERR_SERVER,{}};
      }
      size_t res_len;
      memcpy(&res_len, &first_8_bytes,8); 
      vector <uint8_t> reduce_res (res_len,'\0');
      n_bytes = read(fd2[0],reduce_res.data(),res_len);
      close(fd2[0]);
      pid = waitpid(0,&status,WUNTRACED);
      return {true, RES_OK, reduce_res};
      //}
      //}
      //else if (WIFSIGNALED(status) != 0) {    // child process send SIGKILL by seccomp
      // else{
      //    close(fd2[0]);
      //    return {false, RES_ERR_SERVER,{}};
      // }
        
      //}
    }
    //////////// NEW FORK CODE //////////////


    // //int fd[2];
    // vector<uint8_t> reduce_result;
    // //pipe(fd);

    // // if(fork()==0)
    // // {
    // //   close(fd[0]);
    // //   prctl(PR_SET_SECCOMP,SECCOMP_MODE_STRICT);
    //   pair <map_func,reduce_func> thepair = funcs->get_mr(mrname);
    //   map_func themap = thepair.first;
    //   reduce_func thereduce = thepair.second;
    //   auto dummy = [](){};
    //   vector<vector<uint8_t>> map_result_v;
    //   kv_store->do_all_readonly([&](auto key, auto val){
    //     vector<uint8_t> map_result = themap(key , val);
    //     map_result_v.push_back(map_result);
    //   },dummy);
    //   reduce_result = thereduce(map_result_v);
    // //   write(fd[1], &reduce_result, sizeof(reduce_result));
    // //   close(fd[1]);
    // //   _exit(EXIT_SUCCESS);
    // // }
    // // else{
    // //   close(fd[1]);
    // //   read(fd[0], &reduce_result, sizeof(reduce_result));
    //   return {true, RES_OK, reduce_result};
    // //   close(fd[1]);
    // //   wait(NULL);
    // //   exit(EXIT_SUCCESS);
    // // }
  }

  /// Shut down the storage when the server stops.  This method needs to close
  /// any open files related to incremental persistence.  It also needs to clean
  /// up any state related to .so files.  This is only called when all threads
  /// have stopped accessing the Storage object.
  virtual void shutdown() {
    fclose(storage_file);
    funcs->shutdown();
  }

  /// Write the entire Storage object to the file specified by this.filename. To
  /// ensure durability, Storage must be persisted in two steps.  First, it must
  /// be written to a temporary file (this.filename.tmp).  Then the temporary
  /// file can be renamed to replace the older version of the Storage object.
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t save_file() {
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
    return load_file_helper(auth_table, kv_store, filename, storage_file, mru);
  }
};

/// Create an empty Storage object and specify the file from which it should be
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
Storage *storage_factory(const std::string &fname, size_t buckets, size_t upq,
                         size_t dnq, size_t rqq, double qd, size_t top,
                         const std::string &admin) {
  return new MyStorage(fname, buckets, upq, dnq, rqq, qd, top, admin);
}
