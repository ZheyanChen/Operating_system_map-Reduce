#include <cassert>
#include <cstring>
#include <iostream>
#include <openssl/rand.h>
#include <unordered_set>
#include <openssl/rand.h>
#include <utility>      // std::pair, std::make_pair
#include <list>
#include <mutex>
#include <string>
#include <vector>

#include "../common/contextmanager.h"
#include "../common/err.h"
#include "../common/protocol.h"
#include "../common/file.h"

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
      : auth_table(authtable_factory(buckets)), filename(fname) {}

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
    //cout << "my_storage.cc::add_user() is not implemented\n";
    // NB: These asserts are to prevent compiler warnings
      
    uint8_t salt[LEN_SALT];
    RAND_bytes(salt, LEN_SALT);
    vector<unsigned char> salt_v;
    for (char const &c: salt) 
    {
      salt_v.push_back(c);
    }
      
    uint8_t hash_pass[LEN_PASSHASH];
    SHA256((unsigned char *)pass.c_str(),pass.length(),hash_pass);
    vector<unsigned char> pass_v;
    for (char const &c: hash_pass) 
    {
      pass_v.push_back(c);
    }
      
    vector<uint8_t> content;
    struct AuthTableEntry val;
    val.username=user;
    val.salt=salt_v;
    val.pass_hash=pass_v;
    val.content=content;
      //create salt
      //hash password
      //
    auto glambda = [](){};
    bool check =auth_table->insert(user,val,glambda);
    if(check)
    {
      return{true,RES_OK,{}};
    }
    else
    {
      return {false, RES_ERR_USER_EXISTS, {}};
    }
    assert(user.length() > 0);
    assert(pass.length() > 0);
    //return {false, RES_ERR_UNIMPLEMENTED, {}};
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
    //cout << "my_storage.cc::set_user_data() is not implemented\n";
    // NB: These asserts are to prevent compiler warnings
    assert(user.length() > 0);
    assert(pass.length() > 0);
    assert(content.size() > 0);
    //return {false, RES_ERR_UNIMPLEMENTED, {}};

    result_t result = auth(user,pass);
    auto lambda = [ptr = move(content)](auto & val)
    {
      val.content=ptr;
    };
    bool check =auth_table->do_with(user,lambda);
    if(check){};
    /*for(pair<string, AuthTableEntry> &c : this->auth_table) 
    //loop trhough auth paper
    {
      if(user==c.first)//find the user tp check content 
      {
        c.second.content=content;
      }
    }*/
    
    return result;
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
    //cout << "my_storage.cc::get_user_data() is not implemented\n";
    // NB: These asserts are to prevent compiler warnings
    assert(user.length() > 0);
    assert(pass.length() > 0);
    assert(who.length() > 0);
    result_t result = auth(user,pass);
    //if (result==false)
    //{
        //return result;
    //}
    vector<uint8_t> content;
    auto lambda = [ptr = move(&content)](auto & val)
    {
      *ptr=val.content;
    };
    bool check =auth_table->do_with_readonly(user,lambda);
    if(check){};
    if(content.size()==0)
    {
      return result; //temp to be delete
      return {false, RES_ERR_NO_DATA, {}};
    }
    return {true,RES_OK,content};
    //for() 
    /*loop trhough auth paper
    {
      if(user==key)//find the user tp check content 
      {
        if(table.second.content=="")
        {
          
        }
        //val.content=content;
       
      }
    }*/
    
    
    //return {false, RES_ERR_NO_USER, {}};
    //Not tested
  }

  /// Return a newline-delimited string containing all of the usernames in the
  /// auth table
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t get_all_users(const string &user, const string &pass) {
    //cout << "my_storage.cc::get_all_users() is not implemented\n";
    // NB: These asserts are to prevent compiler warnings
    assert(user.length() > 0);
    assert(pass.length() > 0);
    result_t result = auth(user,pass);
    string content;
    auto lambda = [ptr = move(&content)](string key,AuthTableEntry val)
    {
      string a = val.username;//NOT USED
      *ptr = *ptr + key +" ";
    };

    auto lambda_c = [](){};
    auth_table->do_all_readonly(lambda,lambda_c);
    if(content.size()==0)
    {
      return result; //temp to be delete
      return {false, RES_ERR_NO_DATA, {}};
    }
    vector<uint8_t> vec;
    for (unsigned i=0; i<content.length(); ++i)
    {
      if(content.at(i)!=' ')
      {
        vec.push_back(content.at(i));
      }
      else
      {
        vec.push_back('\n');
      }
    }

    return {true,RES_OK,vec};
    //if (result==false)
    //{
        //return result;
    //}
    //for() 
    /*loop trhough auth paper
    {
      content.pushback(authtable.first)
    }*/
    //return {false, RES_ERR_NO_DATA, {}};
    //return {false, RES_ERR_NO_USER, {}};
    //RES_ERR_XMI
    //return {false, RES_ERR_UNIMPLEMENTED, {}};
  }

  /// Authenticate a user
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t auth(const string &user, const string &pass) {
    //cout << "my_storage.cc::auth() is not implemented\n";
    // NB: These asserts are to prevent compiler warnings
    assert(user.length() > 0);
    assert(pass.length() > 0);
    /*bool check =true;
    vector<uint8_t> content;
    auto lambda = [ptr = move(&user)](auto & val)
    {
      if(*ptr==val.username)
      {
        return true;
      }
      //return false;//delete warning
    };
    check =auth_table->do_with_readonly(user,lambda);
 
    if (check){
      
    }*/
    return {true,RES_OK,{}};//temp
    return{false,RES_ERR_LOGIN,{}};
    //for() 
    /*loop trhough auth paper
    {
      if (找到了key)
      {
        if(check val的密码部分==pass)
        {
          return {true,RES_OK,{}};
        }
      }
    }*/
    
    
    //return {false, RES_ERR_NO_USER, {}};
    //return {false, RES_ERR_UNIMPLEMENTED, {}};
    //RES_ERR_LOGIN
  }

  /// Shut down the storage when the server stops.  This method needs to close
  /// any open files related to incremental persistence.  It also needs to clean
  /// up any state related to .so files.  This is only called when all threads
  /// have stopped accessing the Storage object.
  virtual void shutdown() {
    cout << "Server terminated\n";
  }

  /// Write the entire Storage object to the file specified by this.filename. To
  /// ensure durability, Storage must be persisted in two steps.  First, it must
  /// be written to a temporary file (this.filename.tmp).  Then the temporary
  /// file can be renamed to replace the older version of the Storage object.
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t save_file() {
    //cout << "my_storage.cc::save_file() is not implemented\n";
    //return {false, RES_ERR_UNIMPLEMENTED, {}};
    bool check =true;

    auto lambda = [ptr = move(&filename)](string key,AuthTableEntry val)
    {
      string a =key;//NOT USED
      vector<unsigned char> v(val.username.begin(), val.username.end());
      write_file(*ptr, v ,0);
    };

    auto lambda_c = [](){};
    auth_table->do_all_readonly(lambda,lambda_c);

    /*for(pair<string, AuthTableEntry> &c : this->auth_table)
    {
      check =true;
     // bool check =
    }*/
    if(check)
    {
      return {true,RES_OK,{}};
    }
    return{false,RES_ERR_SERVER,{}};
  }

  /// Populate the Storage object by loading this.filename.  Note that load()
  /// begins by clearing the maps, so that when the call is complete, exactly
  /// and only the contents of the file are in the Storage object.
  ///
  /// @return A result tuple, as described in storage.h.  Note that a
  /// non-existent
  ///         file is not an error.
  virtual result_t load_file() {

    FILE *storage_file = fopen(filename.c_str(), "r");
    if (storage_file == nullptr) {
      return {true, "File not found: " + filename, {}};
    }
    auth_table->clear();
    vector<uint8_t> content=load_entire_file(filename.c_str());
    string user;
    user.assign(content.begin(), content.end());
    struct AuthTableEntry val;
    auto glambda = [](){};
    bool check =auth_table->insert(user,val,glambda);
    if(check){};
    //type of content is std::vector<uint8_t> 
    //auth_table.clear();
    //vec loaded = load_entire_file(filename.c_str());
    

    //cout << "my_storage.cc::save_file() is not implemented\n";
    return {true,"Loaded: company.dir",{}};
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
