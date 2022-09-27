# Build a client and server using the student's files

# The executables will have the suffix .exe
EXESUFFIX = exe

# Names for building the client:
CLIENT_MAIN     = client
CLIENT_CXX      = 
CLIENT_COMMON   = 
CLIENT_PROVIDED = client requests crypto err file net my_crypto

# Names for building the server
SERVER_MAIN     = server
SERVER_CXX      = my_storage my_functable
SERVER_COMMON   = 
SERVER_PROVIDED = crypto err file net my_pool my_crypto server responses      \
                  parsing concurrenthashmap_factories my_quota_tracker my_mru \
                  persist helpers

# Names for building shared objects
SO_CXX    = all_keys odd_key_vals invalid1 invalid2 broken1 broken2
SO_COMMON = 

# NB: This Makefile does not add extra CXXFLAGS

# Pull in the common build rules
include common.mk