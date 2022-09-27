#include <string>
#include <vector>

extern "C" {

/// This mapper returns the key, without doing any work
std::vector<uint8_t> map(std::string &key, std::vector<uint8_t> &) {
  return std::vector<uint8_t>(key.begin(), key.end());
}

/// This reducer concatenates all strings into a newline-delimited list
///
/// NB: It has the wrong name, so KVF should fail
std::vector<uint8_t> reducer(std::vector<std::vector<uint8_t>> &results) {
  std::vector<uint8_t> res;
  for (auto r : results) {
    if (res.size() != 0)
      res.push_back('\n');
    res.insert(res.end(), r.begin(), r.end());
  }
  return res;
}
}