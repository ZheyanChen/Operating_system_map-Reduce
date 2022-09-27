// http://www.cplusplus.com/reference/ctime/time/ is helpful here
#include <deque>
#include <iostream>
#include <memory>
#include <time.h>
#include "quota_tracker.h"

using namespace std;

/// quota_tracker stores time-ordered information about events.  It can count
/// events within a pre-set, fixed time threshold, to decide if a new event can
/// be allowed without violating a quota.
class my_quota_tracker : public quota_tracker {
  struct amount_time { 
    size_t amount;
    time_t time;  
  };
  deque<amount_time> thequota;
  size_t max_amount;
  double theduration;

public:
  /// Construct a tracker that limits usage to quota_amount per quota_duration
  /// seconds
  ///
  /// @param amount   The maximum amount of service
  /// @param duration The time over which the service maximum can be spread out
  my_quota_tracker(size_t amount, double duration) {
    max_amount = amount;
    theduration = duration;
  }

  /// Destruct a quota tracker
  virtual ~my_quota_tracker() {}

  /// Decide if a new event is permitted, and if so, add it.  The attempt is
  /// allowed if it could be added to events, while ensuring that the sum of
  /// amounts for all events within the duration is less than q_amnt.
  ///
  /// @param amount The amount of the new request
  ///
  /// @return false if the amount could not be added without violating the
  ///         quota, true if the amount was added while preserving the quota
  virtual bool check_add(size_t amount) {
    size_t amount_total=amount;
    time_t timer;
    time(&timer);
    auto it = thequota.begin();

    while (it != thequota.end())
    {
      if(difftime(timer,(*it).time) < theduration)
      {
        amount_total+=(*it).amount;
        ++ it;
      }
      else {   // encounter expiration quota
        while (it != thequota.end()) {
          thequota.pop_back(); //remove expired quota
        }
        break;
      }

    }
    if(amount_total <= max_amount)
    {
      amount_time at;
      at.amount = amount;
      at.time = timer;
      thequota.push_back(at);/*push the into quota*/
      return true;
    }
    else
    {
      return false;
    }
  }
};

/// Construct a tracker that limits usage to quota_amount per quota_duration
/// seconds
///
/// @param amount   The maximum amount of service
/// @param duration The time over which the service maximum can be spread out
quota_tracker *quota_factory(size_t amount, double duration) {
  return new my_quota_tracker(amount, duration);
}