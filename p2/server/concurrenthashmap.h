#include <cassert>
#include <functional>
#include <iostream>
#include <list>
#include <mutex>
#include <string>
#include <vector>

#include "map.h"

using namespace std;

/// ConcurrentHashMap is a concurrent implementation of the Map interface (a
/// Key/Value store).  It is implemented as a vector of buckets, with one lock
/// per bucket.  Since the number of buckets is fixed, performance can suffer if
/// the thread count is high relative to the number of buckets.  Furthermore,
/// the asymptotic guarantees of this data structure are dependent on the
/// quality of the bucket implementation.  If a vector is used within the bucket
/// to store key/value pairs, then the guarantees will be poor if the key range
/// is large relative to the number of buckets.  If an unordered_map is used,
/// then the asymptotic guarantees should be strong.
///
/// The ConcurrentHashMap is templated on the Key and Value types.
///
/// This map uses std::hash to map keys to positions in the vector.  A
/// production map should use something better.
///
/// This map provides strong consistency guarantees: every operation uses
/// two-phase locking (2PL), and the lambda parameters to methods enable nesting
/// of 2PL operations across maps.
///
/// @param K The type of the keys in this map
/// @param V The type of the values in this map
template <typename K, typename V> class ConcurrentHashMap : public Map<K, V> {

size_t buckets_num; // by default private
public:
  /// Construct by specifying the number of buckets it should have
  ///
  struct Bucket { 
    list<pair<K,V> > entry;
    mutex mtx;  // a mutex for each bucket
  };
  vector<Bucket*> c_map;   
  /// @param _buckets The number of buckets
  ConcurrentHashMap(size_t _buckets) {
    // std::cout << "ConcurrentHashMap::ConcurrentHashMap() is not implemented";
    // c_map = new vector <Bucket*>[_buckets]; 
    buckets_num = _buckets;
    for (size_t i=0; i<_buckets; i++) {
      c_map.push_back(new Bucket());  // buckets on the heap
    }
  }

  /// Destruct the ConcurrentHashMap
  virtual ~ConcurrentHashMap() {
    // std::cout << "ConcurrentHashMap::~ConcurrentHashMap() is not implemented";
    for (Bucket *b: c_map) {
      delete(b);
    }
  }

  /// Clear the map.  This operation needs to use 2pl
  virtual void clear() {
    // std::cout << "ConcurrentHashMap::clear() is not implemented";
    for (Bucket *b: c_map) {
      if (b->mtx.try_lock())   // lock before operation
      // list<Map<K,V> > &entry = map_bucket.entry;
      // entry.clear();
        b->entry.clear();
    }
    // unlock all the mutex
    for (Bucket *m: c_map) {
      if (!m->mtx.try_lock()) m->mtx.unlock();  // unlock at every level
    }
    
  }

  /// Insert the provided key/value pair only if there is no mapping for the key
  /// yet.
  ///
  /// @param key        The key to insert
  /// @param val        The value to insert
  /// @param on_success Code to run if the insertion succeeds
  ///
  /// @return true if the key/value was inserted, false if the key already
  ///         existed in the table
  virtual bool insert(K key, V val, std::function<void()> on_success) {
    // std::cout << "ConcurrentHashMap::insert() is not implemented";
    size_t index = std::hash<K>()(key) % buckets_num;
    lock_guard<mutex> lock(c_map[index]->mtx);  //auto lock 
    // cout<<"hashmap::insert at index " << index <<'\n';
    // auto list = c_map[index]->entry;  // grab the entire list of pairs
    // for (pair<K,V> &e: list) {
    //   if (e.first == key)
    //     return false;
    // }
    // // not duplicate
    // pair<K,V> new_pair (key,val);
    // list.push_back(new_pair);
    // on_success();
    auto it = c_map[index]->entry.begin();
    while (it != c_map[index]->entry.end()) {
      if ((*it).first == key) return false;
      ++ it;
    }
    pair<K,V> new_pair (key,val);
    c_map[index]->entry.push_back(new_pair);
    on_success();
    return true;
  }

  /// Insert the provided key/value pair if there is no mapping for the key yet.
  /// If there is a key, then update the mapping by replacing the old value with
  /// the provided value
  ///
  /// @param key    The key to upsert
  /// @param val    The value to upsert
  /// @param on_ins Code to run if the upsert succeeds as an insert
  /// @param on_upd Code to run if the upsert succeeds as an update
  ///
  /// @return true if the key/value was inserted, false if the key already
  ///         existed in the table and was thus updated instead
  virtual bool upsert(K key, V val, std::function<void()> on_ins,
                      std::function<void()> on_upd) {
    // std::cout << "ConcurrentHashMap::upsert() is not implemented";
    size_t index = std::hash<K>()(key) % buckets_num;
    // cout<< "Hashmap::upsert bucket_num is " <<buckets_num <<'\n';
    lock_guard<mutex> lock(c_map[index]->mtx);  //auto lock 
    auto it = c_map[index]->entry.begin();
    while (it != c_map[index]->entry.end()) {
      if ((*it).first == key) {
        (*it).second = val;
        on_upd();
        return false;
      }
      ++ it;
    }
    // insert instead
    pair<K,V> new_pair (key,val);
    c_map[index]->entry.push_back(new_pair);
    on_ins();
    return true;
  }

  /// Apply a function to the value associated with a given key.  The function
  /// is allowed to modify the value.
  ///
  /// @param key The key whose value will be modified
  /// @param f   The function to apply to the key's value
  ///
  /// @return true if the key existed and the function was applied, false
  ///         otherwise
  virtual bool do_with(K key, std::function<void(V &)> f) {
    // std::cout << "ConcurrentHashMap::do_with() is not implemented";
    size_t index = std::hash<K>()(key) % buckets_num;
    lock_guard<mutex> lock(c_map[index]->mtx);  //auto lock 
    auto it = c_map[index]->entry.begin();
    while (it != c_map[index]->entry.end()) {
      if ((*it).first == key) {
        f((*it).second);
        return true;
      }
      ++ it;
    }
    // not found key
    return false;
  }

  /// Apply a function to the value associated with a given key.  The function
  /// is not allowed to modify the value.
  ///
  /// @param key The key whose value will be modified
  /// @param f   The function to apply to the key's value
  ///
  /// @return true if the key existed and the function was applied, false
  ///         otherwise
  virtual bool do_with_readonly(K key, std::function<void(const V &)> f) {
    // std::cout << "ConcurrentHashMap::do_with_readonly() is not implemented";
    size_t index = std::hash<K>()(key) % buckets_num;
    lock_guard<mutex> lock(c_map[index]->mtx);  //auto lock 
    auto it = c_map[index]->entry.begin();
    while (it != c_map[index]->entry.end()) {
      if ((*it).first == key) {
        f((*it).second);
        return true;
      }
      ++ it;
    }
    // not found key
    return false;
  }

  /// Remove the mapping from a key to its value
  ///
  /// @param key        The key whose mapping should be removed
  /// @param on_success Code to run if the remove succeeds
  ///
  /// @return true if the key was found and the value unmapped, false otherwise
  virtual bool remove(K key, std::function<void()> on_success) {
    // std::cout << "ConcurrentHashMap::remove() is not implemented";
    size_t index = std::hash<K>()(key) % buckets_num;
    lock_guard<mutex> lock(c_map[index]->mtx);  //auto lock 
    auto it = c_map[index]->entry.begin();
    while (it != c_map[index]->entry.end()) {
      if ((*it).first == key) {
        c_map[index]->entry.erase(it);
        on_success();
        return true;
      }
      ++ it;
    }
    // not found key
    return false;
  }

  /// Apply a function to every key/value pair in the map.  Note that the
  /// function is not allowed to modify keys or values.
  ///
  /// @param f    The function to apply to each key/value pair
  /// @param then A function to run when this is done, but before unlocking...
  ///             useful for 2pl
  virtual void do_all_readonly(std::function<void(const K, const V &)> f,
                               std::function<void()> then) {
    for (size_t i=0; i<buckets_num; i++) {
      c_map[i]->mtx.lock();  // lock first
      auto it = c_map[i]->entry.begin();
      while (it != c_map[i]->entry.end()) {
        f ((*it).first, (*it).second);
        ++ it;
      }
    }
    then();  // acquire all locks
    for (size_t i=0; i<buckets_num; i++) c_map[i]->mtx.unlock();
  }
};
