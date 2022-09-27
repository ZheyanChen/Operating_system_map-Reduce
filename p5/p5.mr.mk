# Build a client and server from the reference solution, but use the student's
# implementation of map/reduce

# The executables will have the suffix p5.mr.exe
EXESUFFIX = p5.mr.exe

# Names for building the client:
CLIENT_MAIN     = client
CLIENT_CXX      = 
CLIENT_COMMON   = 
CLIENT_PROVIDED = client requests crypto my_crypto err file net

# Names for building the server
SERVER_MAIN     = server
SERVER_CXX      = my_storage
SERVER_COMMON   = 
SERVER_PROVIDED = server responses parsing concurrenthashmap_factories      \
                  my_functable my_mru crypto my_crypto err file net my_pool \
                  my_quota_tracker persist helpers

# Names for building shared objects (one .so per SO_CXX)
SO_CXX    = all_keys odd_key_vals invalid1 invalid2 broken1 broken2
SO_COMMON = 

# All warnings should be treated as errors
CXXEXTRA = -Werror

# Pull in the common build rules
include common.mk