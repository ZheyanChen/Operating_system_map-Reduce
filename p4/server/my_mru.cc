#include <deque>
#include <iostream>
#include <mutex>

#include "mru.h"

using namespace std;

/// my_mru maintains a listing of the K most recent elements that have been
/// given to it.  It can be used to produce a "top" listing of the most recently
/// accessed keys.
class my_mru : public mru_manager {
size_t max;
mutex mtx;
deque<string> thedeque;
public:
  /// Construct the mru_manager by specifying how many things it should track
  ///
  /// @param elements The number of elements that can be tracked
  my_mru(size_t elements) {
    max = elements;
  }

  /// Destruct the mru_manager
  virtual ~my_mru() {}

  /// Insert an element into the mru_manager, making sure that (a) there are no
  /// duplicates, and (b) the manager holds no more than /max_size/ elements.
  ///
  /// @param elt The element to insert
  virtual void insert(const std::string &elt) {
    lock_guard <mutex> lock(mtx);
    auto it = thedeque.begin();
    while (it != thedeque.end())
    {
      if((*it) == elt)
      {
        thedeque.erase(it);
        break;
      }
      ++ it;
    }
    if (thedeque.size()==max)
    {
      thedeque.pop_back();
    }
    thedeque.push_front(elt);
  }

  /// Remove an instance of an element from the mru_manager.  This can leave the
  /// manager in a state where it has fewer than max_size elements in it.
  ///
  /// @param elt The element to remove
  virtual void remove(const std::string &elt) {
    lock_guard <mutex> lock(mtx);
    auto it = thedeque.begin();
    while (it != thedeque.end())
    {
      if((*it) == elt)
      {
        thedeque.erase(it);
        break;
      }
      ++ it;
    }
  }

  /// Clear the mru_manager
  virtual void clear() {
    lock_guard<mutex> lock(mtx);
    auto it = thedeque.begin();
    while (it != thedeque.end())
    {
      thedeque.erase(it);
      ++ it;
    }
  }

  /// Produce a concatenation of the top entries, in order of popularity
  ///
  /// @return A newline-separated list of values
  virtual std::string get() { 
    lock_guard <mutex> lock(mtx);
    string rv;
    auto it = thedeque.begin();
    while (it != thedeque.end())
    {
      rv+=(*it);
      ++ it;
      if (it!=thedeque.end())
      {
        rv+='\n';
      }  
    }
    return rv;
  }
};

/// Construct the mru_manager by specifying how many things it should track
///
/// @param elements The number of elements that can be tracked in MRU fashion
///
/// @return An mru manager object
mru_manager *mru_factory(size_t elements) { return new my_mru(elements); }