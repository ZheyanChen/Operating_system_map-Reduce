#include <cstdio>
#include <string>
#include <vector>

#include "../server/functypes.h"

extern "C" {

/// This mapper returns the key, without doing any work.  It also opens a file,
/// which should trigger a seccomp violation
std::vector<uint8_t> map(std::string &key, std::vector<uint8_t> &) {
  FILE *f = fopen("./tmp.dat", "w");
  fwrite(key.c_str(), sizeof(char), key.length(), f);
  fclose(f);
  return std::vector<uint8_t>(key.begin(), key.end());
}

/// This reducer concatenates all strings into a newline-delimited list
std::vector<uint8_t> reduce(std::vector<std::vector<uint8_t>> &results) {
  std::vector<uint8_t> res;
  for (auto r : results) {
    if (res.size() != 0)
      res.push_back('\n');
    res.insert(res.end(), r.begin(), r.end());
  }
  return res;
}
}
