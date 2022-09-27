#pragma once

#include <openssl/sha.h>
#include <string>

/// protocol.h defines the messages that a client may send, and the responses a
/// server will provide.  Note that the entire request is a single byte stream,
/// as is the entire response.  The entire communication between client and
/// server should consist of just two messages.  First, the client sends a
/// message (the request), and then the server sends a reply message (the
/// response).
///
/// Different parts of a message may be encrypted in different ways.  We
/// indicate this with the 'enc()' function.  The expression 'enc(x, y)'
/// indicates that y should be encrypted using key x.  Both RSA and AES
/// encryption are used.  A unique AES key (aeskey) should be generated each
/// time the client sends an AES-encrypted message to the server.  An RSA key
/// (rsakey) is generated by the server once.
///
/// A request always begins with a fixed-size RSA-encrypted block of bytes
/// (@rblock), followed by a variable-size AES-encrypted block of bytes
/// (@ablock).  The only exception to this is the KEY request, which consists of
/// a fixed-size unencrypted block of bytes (@kblock). The @kblock or @rblock
/// will always be LEN_RKBLOCK bytes, regardless of whether it is an
/// RSA-encrypted block or the "KEY" message.  KEY messages are padded with '\0'
/// characters. RSA-encrypted blocks are padded with random bytes.  In the
/// discussion below, this padding is represented by the function pad0() or
/// padR().
///
/// To make parsing as easy as possible, there will be some minor inefficiency
/// that increases regularity.  The function null(x) indicates a sequence of x
/// consecutive \0 characters.
///
/// When there is an AES block, its length will be given as part of the RSA
/// block.  Note that this is the length of the *encrypted* @ablock.
///
/// In describing message formats, we use the dot ('.') to indicate
/// concatenation.  So "ABC"."DEF" will consist of 6 bytes, and will be the
/// characters "ABCDEF".  When 'len()' appears in a description, this indicates
/// that an 8-byte *binary* value will be provided as a length.  You are allowed
/// to assume that only x86 machines will be used (little endian).  The
/// expression <EOF> represents the end of a file / the closing of a connection.
/// It does not introduce new bytes into the block.
///
/// Finally, note that some error messages do not correspond directly to any
/// specific request, but are possible nonetheless (i.e., RES_ERR_INV_CMD).

////////////////////////////////////////////////////////////////
// Below are the definitions needed for Assignment #1
////////////////////////////////////////////////////////////////

//
// Constants
//

/// Maximum length of a user name
const int LEN_UNAME = 64;

/// Maximum length of a user's actual password
const int LEN_PASSWORD = 64;

/// Maximum length of a hashed password
const int LEN_PASSHASH = SHA256_DIGEST_LENGTH;

/// Maximum length of a user's profile file
const int LEN_PROFILE_FILE = 1048576;

/// Length of an rblock or kblock
const int LEN_RKBLOCK = 256;

/// Length of an RSA public key
///
/// NB: It would be better not to hard-code this, since it's not defined by us,
///     but by OpenSSL
const int LEN_RSA_PUBKEY = 426;

/// Length of rblock content before it is encrypted
const int LEN_RBLOCK_CONTENT = 128;

/// Length of salt
const int LEN_SALT = 16;

//
// Request Messages
//

/// Request the server's public key (@pubkey), to use for subsequent interaction
/// with the server by the client
///
/// @kblock   pad0("PUB_KEY_")
/// @response @pubkey.<EOF>
/// @errors   None
const std::string REQ_KEY = "PUB_KEY_";

/// Request the creation of a new user, with null content.  The user name must
/// not already exist.
///
/// The user name (@u) and user password (@p) must conform to LEN_UNAME and
/// LEN_PASSWORD.
///
/// @rblock   enc(pubkey, padR("REGISTER".aeskey.len(@ablock)))
/// @ablock   enc(aeskey, len(@u).len(@p).null(8).null(8).@u.@p)
/// @response enc(aeskey, "OK").<EOF>       -- Success
///           enc(aeskey, error_code).<EOF> -- Error (see @errors)
///           ERR_CRYPTO.<EOF>              -- Error (see @errors)
/// @errors   ERR_USER_EXISTS -- @u already exists as a user
///           ERR_REQUEST_FMT -- Server unable to extract @u or @p from request
///           ERR_CRYPTO      -- Server could not decrypt @ablock
const std::string REQ_REG = "REGISTER";

/// Force the server to stop.  @u and @p represent a valid user's username and
/// password.
///
/// The user name (@u) and user password (@p) must conform to LEN_UNAME and
/// LEN_PASSWORD.
///
/// Note that a real server should never let a client cause it to stop.  This is
/// a convenience request to help the professor and TAs grade your assignment.
///
/// @rblock   enc(pubkey, padR("EXIT____".aeskey.len(@ablock)))
/// @ablock   enc(aeskey, len(@u).len(@p).null(8).null(8).@u.@p)
/// @response enc(aeskey, "OK").<EOF>       -- Success
///           enc(aeskey, error_code).<EOF> -- Error (see @errors)
///           ERR_CRYPTO.<EOF>              -- Error (see @errors)
/// @errors   ERR_LOGIN       -- @u is not a valid user
///           ERR_LOGIN       -- @p is not @u's password
///           ERR_REQUEST_FMT -- Server unable to extract @u or @p from request
///           ERR_CRYPTO      -- Server could not decrypt @ablock
const std::string REQ_BYE = "EXIT____";

/// Force the server to send all its data to disk.  @u and @p represent a valid
/// user's username and password.
///
/// The user name (@u) and user password (@p) must conform to LEN_UNAME and
/// LEN_PASSWORD.
///
/// Note that a real server should never let a client cause it to do this.  This
/// is a convenience request to help the professor and TAs grade your
/// assignment.
///
/// @rblock   enc(pubkey, padR("PERSIST_".aeskey.len(@ablock)))
/// @ablock   enc(aeskey, len(@u).len(@p).null(8).null(8).@u.@p)
/// @response enc(aeskey, "OK").<EOF>       -- Success
///           enc(aeskey, error_code).<EOF> -- Error (see @errors)
///           ERR_CRYPTO.<EOF>              -- Error (see @errors)
/// @errors   ERR_LOGIN       -- @u is not a valid user
///           ERR_LOGIN       -- @p is not @u's password
///           ERR_REQUEST_FMT -- Server unable to extract @u or @p from request
///           ERR_CRYPTO      -- Server could not decrypt @ablock
const std::string REQ_SAV = "PERSIST_";

/// Allow user @u (with password @p) to set her profile content to the byte
/// stream @b.
///
/// The user name (@u) and user password (@p) must conform to LEN_UNAME and
/// LEN_PASSWORD.  @b must be no more than LEN_PROFILE_FILE bytes.
///
/// @rblock   enc(pubkey, padR("SETPFILE".aeskey.len(@ablock)))
/// @ablock   enc(aeskey, len(@u).len(@p).len(@b).null(8).@u.@p.@b)
/// @response enc(aeskey, "OK").<EOF>       -- Success
///           enc(aeskey, error_code).<EOF> -- Error (see @errors)
///           ERR_CRYPTO.<EOF>              -- Error (see @errors)
/// @errors   ERR_LOGIN       -- @u is not a valid user
///           ERR_LOGIN       -- @p is not @u's password
///           ERR_REQUEST_FMT -- Server unable to extract @u or @p or @b from
///                              request
///           ERR_CRYPTO      -- Server could not decrypt @ablock
const std::string REQ_SET = "SETPFILE";

/// Allow user @u (with password @p) to fetch the profile content @c associated
/// with user @w.
///
/// The user name (@u) and user password (@p) must conform to LEN_UNAME and
/// LEN_PASSWORD.  @w must be no more than LEN_UNAME bytes.
///
/// @rblock   enc(pubkey, padR("GETPFILE".aeskey.len(@ablock)))
/// @ablock   enc(aeskey, len(@u).len(@p).len(@w).null(8).@u.@p.@w)
/// @response enc(aeskey, "OK".len(@c).@c).<EOF>    -- Success
///           enc(aeskey, error_code).<EOF>         -- Error (see @errors)
///           ERR_CRYPTO.<EOF>                      -- Error (see @errors)
/// @errors   ERR_LOGIN       -- @u is not a valid user
///           ERR_LOGIN       -- @p is not @u's password
///           ERR_NO_USER     -- @w is not a valid user
///           ERR_NO_DATA     -- @w has a null profile content
///           ERR_REQUEST_FMT -- Server unable to extract @u or @p or @w from
///                              request
///           ERR_CRYPTO      -- Server could not decrypt @ablock
const std::string REQ_GET = "GETPFILE";

/// Allow user @u (with password @p) to get a newline-separated list (@l) of the
/// names of all the users.  @u will appear in @l, @l will not be sorted, and @l
/// will not have a trailing newline.
///
/// The user name (@u) and user password (@p) must conform to LEN_UNAME and
/// LEN_PASSWORD.
///
/// @rblock   enc(pubkey, padR("ALLUSERS".aeskey.len(@ablock)))
/// @ablock   enc(aeskey, len(@u).len(@p).null(8).null(8).@u.@p)
/// @response enc(aeskey, "OK".len(@l).@l).<EOF>    -- Success
///           enc(aeskey, error_code).<EOF>         -- Error (see @errors)
///           ERR_CRYPTO.<EOF>                      -- Error (see @errors)
/// @errors   ERR_LOGIN       -- @u is not a valid user
///           ERR_LOGIN       -- @p is not @u's password
///           ERR_REQUEST_FMT -- Server unable to extract @u or @p from request
///           ERR_CRYPTO      -- Server could not decrypt @ablock
const std::string REQ_ALL = "ALLUSERS";

//
// Response Messages
//

/// Response code to indicate that the command was successful
const std::string RES_OK = "___OK___";

/// Response code to indicate that the registered user already exists
const std::string RES_ERR_USER_EXISTS = "ERR_USER_EXISTS";

/// Response code to indicate that the client gave a bad username or password
const std::string RES_ERR_LOGIN = "ERR_LOGIN";

/// Response code to indicate that the client request was improperly formatted
const std::string RES_ERR_REQ_FMT = "ERR_REQ_FMT";

/// Response code to indicate that there is no data to send back
const std::string RES_ERR_NO_DATA = "ERR_NO_DATA";

/// Response code to indicate that the user being looked up is invalid
const std::string RES_ERR_NO_USER = "ERR_NO_USER";

/// Response code to indicate that the requested command doesn't exist
const std::string RES_ERR_INV_CMD = "ERR_INVALID_COMMAND";

/// Response code to indicate that the client didn't get as much data as
/// expected
const std::string RES_ERR_XMIT = "ERR_XMIT";

/// Response code to indicate that the client data can't be decrypted with the
/// provided AES key
const std::string RES_ERR_CRYPTO = "ERR_CRYPTO";

/// Response code to indicate that the server had an internal error, such as a
/// bad read from a file, error creating a salt, or failure to fork()
const std::string RES_ERR_SERVER = "ERR_SERVER";

/// Response code to indicate that something has not been implemented
const std::string RES_ERR_UNIMPLEMENTED = "ERR_UNIMPLEMENTED";

////////////////////////////////////////////////////////////////
// Below are the additions for Assignment #2
////////////////////////////////////////////////////////////////

//
// Constants
//

/// Maximum length of a key in the key-value store
const int LEN_KEY = 1024;

/// Maximum length of a value in the key-value store
const int LEN_VAL = 1048576;

//
// Request Messages
//

/// Allow user @u (with password @p) to set previously-unset string key @k to
/// value @v
///
/// The user name (@u) and user password (@p) must conform to LEN_UNAME and
/// LEN_PASSWORD.  @k and @v must conform to LEN_KEY and LEN_VAL.
///
/// @rblock   enc(pubkey, padR("KVINSERT".aeskey.len(@ablock)))
/// @ablock   enc(aeskey, len(@u).len(@p).len(@k).len(@v).@u.@p.@k.@v)
/// @response enc(aeskey, "OK").<EOF>       -- Success
///           enc(aeskey, error_code).<EOF> -- Error (see @errors)
///           ERR_CRYPTO.<EOF>              -- Error (see @errors)
/// @errors   ERR_LOGIN       -- @u is not a valid user
///           ERR_LOGIN       -- @p is not @u's password
///           ERR_KEY         -- @k already has a value
///           ERR_REQUEST_FMT -- Server unable to extract @u or @p or @k or @v
///                              from request
///           ERR_CRYPTO      -- Server could not decrypt @ablock
///           ERR_QUOTA_REQ   -- Client exceeded request quota
///           ERR_QUOTA_UP    -- Client exceeded upload bandwidth quota
const std::string REQ_KVI = "KVINSERT";

/// Allow user @u (with password @p) to fetch the value @v associated with key
/// @k
///
/// The user name (@u) and user password (@p) must conform to LEN_UNAME and
/// LEN_PASSWORD.  @k must be no more than LEN_KEY bytes.
///
/// @rblock   enc(pubkey, padR("KVGETONE".aeskey.len(@ablock)))
/// @ablock   enc(aeskey, len(@u).len(@p).len(@k).null(8).@u.@p.@k)
/// @response enc(aeskey, "OK".len(@v).@v).<EOF>    -- Success
///           enc(aeskey, error_code).<EOF>         -- Error (see @errors)
///           ERR_CRYPTO.<EOF>                      -- Error (see @errors)
/// @errors   ERR_LOGIN       -- @u is not a valid user
///           ERR_LOGIN       -- @p is not @u's password
///           ERR_KEY         -- @k does not have a value mapped to it
///           ERR_REQUEST_FMT -- Server unable to extract @u or @p or @k from
///                              request
///           ERR_CRYPTO      -- Server could not decrypt @ablock
///           ERR_QUOTA_REQ   -- Client exceeded request quota
///           ERR_QUOTA_DOWN  -- Client exceeded download bandwidth quota
const std::string REQ_KVG = "KVGETONE";

/// Allow user @u (with password @p) to delete the mapping for key @k
///
/// The user name (@u) and user password (@p) must conform to LEN_UNAME and
/// LEN_PASSWORD.  @k myst be no more than LEN_KEY bytes.
///
/// @rblock   enc(pubkey, padR("KVDELETE".aeskey.len(@ablock)))
/// @ablock   enc(aeskey, len(@u).len(@p).len(@k).null(8).@u.@p.@k)
/// @response enc(aeskey, "OK").<EOF>       -- Success
///           enc(aeskey, error_code).<EOF> -- Error (see @errors)
///           ERR_CRYPTO.<EOF>              -- Error (see @errors)
/// @errors   ERR_LOGIN       -- @u is not a valid user
///           ERR_LOGIN       -- @p is not @u's password
///           ERR_KEY         -- @k does not have a value mapped to it
///           ERR_REQUEST_FMT -- Server unable to extract @u or @p or @k from
///                              request
///           ERR_CRYPTO      -- Server could not decrypt @ablock
///           ERR_QUOTA_REQ   -- Client exceeded request quota
const std::string REQ_KVD = "KVDELETE";

/// Allow user @u (with password @p) to "upsert" a mapping from key @k to value
/// @v.  This will change the mapping if @k is already mapped in the key/value
/// store, and will create a new mapping if @k is not yet mapped to any value.
///
/// The user name (@u) and user password (@p) must conform to LEN_UNAME and
/// LEN_PASSWORD.  @k and @v must conform to LEN_KEY and LEN_VAL.
///
/// @rblock   enc(pubkey, padR("KVUPDATE".aeskey.len(@ablock)))
/// @ablock   enc(aeskey, len(@u).len(@p).len(@k).len(@v).@u.@p.@k.@v)
/// @response enc(aeskey, "OKINS").<EOF>    -- Success as insert
///           enc(aeskey, "OKUPD").<EOF>    -- Success as update
///           enc(aeskey, error_code).<EOF> -- Error (see @errors)
///           ERR_CRYPTO.<EOF>              -- Error (see @errors)
/// @errors   ERR_LOGIN       -- @u is not a valid user
///           ERR_LOGIN       -- @p is not @u's password
///           ERR_REQUEST_FMT -- Server unable to extract @u or @p or @k or @v
///                              from request
///           ERR_CRYPTO      -- Server could not decrypt @ablock
///           ERR_QUOTA_REQ   -- Client exceeded request quota
///           ERR_QUOTA_UP    -- Client exceeded upload bandwidth quota
const std::string REQ_KVU = "KVUPDATE";

/// Allow user @u (with password @p) to get a newline-separated list (@l) of the
/// keys in the key/value store.
///
/// The user name (@u) and user password (@p) must conform to LEN_UNAME and
/// LEN_PASSWORD.
///
/// @rblock   enc(pubkey, padR("KVGETALL".aeskey.len(@ablock)))
/// @ablock   enc(aeskey, len(@u).len(@p).null(8).null(8).@u.@p)
/// @response enc(aeskey, "OK".len(@l).@l).<EOF>    -- Success
///           enc(aeskey, error_code).<EOF>         -- Error (see @errors)
///           ERR_CRYPTO.<EOF>                      -- Error (see @errors)
/// @errors   ERR_LOGIN       -- @u is not a valid user
///           ERR_LOGIN       -- @p is not @u's password
///           ERR_NO_DATA     -- There are no key/value pairs to return
///           ERR_REQUEST_FMT -- Server unable to extract @u or @p from request
///           ERR_CRYPTO      -- Server could not decrypt @ablock
///           ERR_QUOTA_REQ   -- Client exceeded request quota
///           ERR_QUOTA_DOWN  -- Client exceeded download bandwidth quota
const std::string REQ_KVA = "KVGETALL";

//
// Response Messages
//

/// Response code to indicate that the upsert command was successful as an
/// insert
const std::string RES_OKINS = "OK_INSERT";

/// Response code to indicate that the upsert command was successful as an
/// update
const std::string RES_OKUPD = "OK_UPDATE";

/// Response code to indicate that there was an error when searching for the
/// given key
const std::string RES_ERR_KEY = "ERR_KEY";
