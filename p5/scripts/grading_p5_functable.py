#!/usr/bin/python3
import cse303

# Configure constants and users
cse303.indentation = 80
cse303.verbose = cse303.check_args_verbose()
alice = cse303.UserConfig("alice", "alice_is_awesome")
fakealice = cse303.UserConfig("alice", "not_alice_password")
bob = cse303.UserConfig("bob", "bob_is_awesome")
chris = cse303.UserConfig("chris", "i_heart_cats")
so1 = "./solutions/all_keys.so"
so2 = "./solutions/odd_key_vals.so"
so3 = "./solutions/invalid1.so"
so4 = "./solutions/invalid2.so"
so5 = "./solutions/broken1.so"
so6 = "./solutions/broken2.so"
mrfile = "mr_file_result"
makefiles = ["Makefile", "p5.mr.mk", "p5.functable.mk"]

# Create objects with server and client configuration
server = cse303.ServerConfig("./obj64/server.exe", "9999", "rsa", "company.dir", "4", "1024", "1", "1048576", "1048576", "4096", "2", "alice")
client = cse303.ClientConfig("./obj64/client.exe", "localhost", "9999", "localhost.pub")

# Check if we should use solution server or client
cse303.override_exe(server, client)

# Set up a clean slate before getting started
cse303.line()
print("Getting ready to run tests")
cse303.line()
cse303.makeclean() # make clean
cse303.clean_common_files(server, client) # .pub, .pri, .dir files
cse303.killprocs()
cse303.build(makefiles)
cse303.leftmsg("Copying files with student map/reduce into place")
cse303.copyexefile("obj64/server.p5.functable.exe", "obj64/server.exe")
cse303.copyexefile("obj64/client.p5.functable.exe", "obj64/client.exe")
cse303.okmsg()

print()
cse303.line()
print("Initializing some users")
cse303.line()
server.pid = cse303.do_cmd_a("Starting server:", [
    "Listening on port "+server.port+" using (key/data) = (rsa, "+server.dirfile+")",
    "Generating RSA keys as ("+server.keyfile+".pub, "+server.keyfile+".pri)",
    "File not found: " + server.dirfile], server.launchcmd())
cse303.waitfor(2)
cse303.do_cmd("Registering new user alice.", "___OK___", client.reg(alice), server)
cse303.after(server.pid) # need an extra cleanup to handle the KEY that was sent by first REG
cse303.do_cmd("Registering new user bob.", "___OK___", client.reg(bob), server)

print()
cse303.line()
print("Test #1: KVF Authentication")
cse303.line()
cse303.do_cmd("Registering function with non-admin user.", "ERR_LOGIN", client.kvF(bob, "mr2", so1), server)
cse303.do_cmd("Registering function with invalid user.", "ERR_LOGIN", client.kvF(chris, "mr2", so1), server)
cse303.do_cmd("Registering function with bad password.", "ERR_LOGIN", client.kvF(fakealice, "mr2", so1), server)
cse303.do_cmd("Registering function with administrator.", "___OK___", client.kvF(alice, "all_keys", so1), server)
cse303.do_cmd("Re-registering function.", "ERR_FUNC", client.kvF(alice, "all_keys", so1), server)
cse303.do_cmd("Registering .so with invalid map().", "ERR_SO", client.kvF(alice, "broken1", so5), server)
cse303.do_cmd("Registering .so with invalid reduce().", "ERR_SO", client.kvF(alice, "broken2", so6), server)

cse303.do_cmd("Stopping server.", "___OK___", client.bye(alice), server)
cse303.await_server("Waiting for server to shut down.", "Server terminated", server)
cse303.clean_common_files(server, client)
print()
