#include <atomic>
#include <cassert>
#include <dlfcn.h>
#include <iostream>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "../common/contextmanager.h"
#include "../common/err.h"
#include "../common/file.h"
#include "../common/protocol.h"

#include "functable.h"
#include "functypes.h"

using namespace std;

/// func_table is a table that stores functions that have been registered with
/// our server, so that they can be invoked by clients on the key/value pairs in
/// kv_store.
class my_functable : public FuncTable {
unordered_map< string, pair<map_func, reduce_func> > themap;
shared_mutex mtx;
vector<void *> list_of_handlers;
vector<string> list_of_fds;

public:
  /// Construct a function table for storing registered functions
  my_functable() {}

  /// Destruct a function table
  virtual ~my_functable() {}

  /// Register the map() and reduce() functions from the provided .so, and
  /// associate them with the provided name.
  ///
  /// @param mrname The name to associate with the functions
  /// @param so     The so contents from which to find the functions
  ///
  /// @return a status message
  virtual std::string register_mr(const std::string &mrname,
                                  const std::vector<uint8_t> &so) {
    lock_guard<shared_mutex> lock(mtx); 
    auto exist_flag = themap.find(mrname);
    if (exist_flag ==themap.end()) { //map/reduce not exists 
      string filedir = SO_PREFIX + mrname+".so";
      list_of_fds.push_back(filedir);
      FILE *fd = fopen(filedir.c_str(),"w+");
      fwrite(so.data(),1,so.size(),fd);
      fclose(fd);
      void * dl_handler = dlopen(filedir.c_str(),RTLD_LAZY);
      if (dl_handler == NULL) 
        return RES_ERR_SO;
      list_of_handlers.push_back(dl_handler);
      auto map_so = (map_func) dlsym(dl_handler,MAP_FUNC_NAME.c_str());
      auto reduce_so = (reduce_func) dlsym(dl_handler,REDUCE_FUNC_NAME.c_str());
      if (map_so == NULL) 
        return RES_ERR_SO;
      else if (reduce_so == NULL) 
        return RES_ERR_SO;
      pair <map_func,reduce_func> newpair (map_so,reduce_so);
      themap.insert({mrname,newpair});
      return RES_OK;
    }
    else return RES_ERR_FUNC;

  }

  /// Get the (already-registered) map() and reduce() functions associated with
  /// a name.
  ///
  /// @param name The name with which the functions were mapped
  ///
  /// @return A pair of function pointers, or {nullptr, nullptr} on error
  virtual std::pair<map_func, reduce_func> get_mr(const std::string &mrname) {
    lock_guard<shared_mutex> lock(mtx); 
    auto it = themap.begin();
    while (it != themap.end()) 
    {
      if ((*it).first==mrname) 
      {
        return {(*it).second.first,(*it).second.second};
      }
      ++ it;
    }
    return {nullptr, nullptr};
  }

  /// When the function table shuts down, we need to de-register all the .so
  /// files that were loaded.
  virtual void shutdown() {
    auto it = list_of_handlers.begin();
    while (it != list_of_handlers.end()) {
      dlclose(*it);
      ++ it;
    }

    // clear the map
    themap.clear();

    // delete so files
    for (auto &filename: list_of_fds) {
      remove(filename.c_str());
    }
  }
};

/// Create a FuncTable
FuncTable *functable_factory() { return new my_functable(); };