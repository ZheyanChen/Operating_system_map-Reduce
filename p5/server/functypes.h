#pragma once

#include <string>
#include <vector>

/// A pointer to a function that takes a string and vector and returns a
/// vector
typedef std::vector<uint8_t> (*map_func)(std::string &, std::vector<uint8_t> &);

/// A pointer to a function that takes a vector of vectors and returns a vector
typedef std::vector<uint8_t> (*reduce_func)(
    std::vector<std::vector<uint8_t>> &);

/// A prefix to use when generating unique names for .so files
const std::string SO_PREFIX = "./codecache";

/// The C name for map functions extracted from .so files
const std::string MAP_FUNC_NAME = "map";

/// The C name for reduce functions extracted from .so files
const std::string REDUCE_FUNC_NAME = "reduce";
