#include <atomic>
#include <condition_variable>
#include <functional>
#include <iostream>
#include <queue>
#include <thread>
#include <unistd.h>

#include "pool.h"

using namespace std;

class my_pool : public thread_pool {
  // private variables
  mutex mtx;
  queue<int> q;  //queue holding socket sds
  vector<thread> thread_list;  // thread lists
  int num_threads;  // # of threads
  condition_variable cv;
  atomic<bool> stall;
  function<bool(int)> execute; 
  function<void()> shut_down;
public:
  /// construct a thread pool by providing a size and the function to run on
  /// each element that arrives in the queue
  ///
  /// @param size    The number of threads in the pool
  /// @param handler The code to run whenever something arrives in the pool
  my_pool(int size, function<bool(int)> handler) {
    // cout << "my_pool::my_pool() is not implemented";
    num_threads = size;
    stall = false; 
    execute = handler;    // assign the lambda func
    // define a thread callable function 
    auto thread_callable = [&] () {
      while (true) {
        int sd;
        {
          unique_lock <mutex> lk(mtx);
          cv.wait(lk,[&] {
            return !q.empty() || stall;   // wait on predicate to be true (q not empty or stop)
          });
          if (stall) return;  // return from the pool constructor
          sd = q.front();
          q.pop();
        }   // realse unique lock over here
        bool status = execute(sd);
        close(sd);
        if (status) break;
      }
      stall = true;
      shut_down();
    };

    for (int i=0; i<num_threads; i++) {
      thread_list.push_back(thread(thread_callable));
    }
  }

  /// destruct a thread pool
  virtual ~my_pool() = default;

  /// Allow a user of the pool to provide some code to run when the pool decides
  /// it needs to shut down.
  ///
  /// @param func The code that should be run when the pool shuts down
  virtual void set_shutdown_handler(function<void()> func) {
    // cout << "my_pool::set_shutdown_handler() is not implemented";
    shut_down = func;
  }

  /// Allow a user of the pool to see if the pool has been shut down
  virtual bool check_active() {
    // cout << "my_pool::check_active() is not implemented";
    return !stall;
  }

  /// Shutting down the pool can take some time.  await_shutdown() lets a user
  /// of the pool wait until the threads are all done servicing clients.
  virtual void await_shutdown() {
    // cout << "my_pool::await_shutdown() is not implemented";
    {
      lock_guard<mutex> lock(mtx);
      cv.notify_all();
    }
    for (int i =0; i< num_threads; i++) {      // block caller thread
      thread_list[i].join();
    }
  }

  /// When a new connection arrives at the server, it calls this to pass the
  /// connection to the pool for processing.
  ///
  /// @param sd The socket descriptor for the new connection
  virtual void service_connection(int sd) {
    // cout << "my_pool::service_connection() is not implemented";
    {
      lock_guard<mutex> lock(mtx);
      q.push(sd);
    }
    cv.notify_one();  // sd queue is not empty 
  }
};

/// Create a thread_pool object.
///
/// We use a factory pattern (with private constructor) to ensure that anyone
thread_pool *pool_factory(int size, function<bool(int)> handler) {
  return new my_pool(size, handler);
}
