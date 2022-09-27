#include <string>
#include <vector>

extern "C" {

/// This mapper returns the value, but only if the integer interpretation of the
/// bytes of the key starting at the second position results in an odd number
std::vector<uint8_t> map(std::string &key, std::vector<uint8_t> &val) {
  return ((atoi(key.c_str() + 1) & 1)) ? val : std::vector<uint8_t>();
}

/// This reducer concatenates all results, twice each, into a newline-delimited
/// list
std::vector<uint8_t> reduce(std::vector<std::vector<uint8_t>> &results) {
  std::vector<uint8_t> res;
  for (auto r : results) {
    if (r.size() > 0) {
      if (res.size() != 0)
        res.push_back('\n');
      res.insert(res.end(), r.begin(), r.end());
      res.insert(res.end(), r.begin(), r.end());
    }
  }
  return res;
}
}