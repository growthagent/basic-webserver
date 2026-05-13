# NOTE: We probably want to split this into several (sub-)modules as we add more functionality and
# a natural structure becomes apparent.
module [
  hash!,
  hash_file!,
  decrypt_aes256_gcm!,
  encrypt_aes256_gcm!,
  pbkdf2_hmac_sha256!,
  random_bytes!,
  bcrypt_hash!,
  bcrypt_verify!,
]

import Host
import File exposing [IOErr]
import Path exposing [Path]

## Hash bytes and return the lowercase-hex digest.
##
## `algorithm` must be one of `"SHA-1"`, `"SHA-256"`, `"SHA-384"`, `"SHA-512"`.
## Passing any other value is a programmer bug and panics the host.
##
## Idiomatic Roc would use a tag union here (e.g. `[Sha1, Sha256, ...]`),
## but a platform-defined union currently trips the Roc compiler's alias
## analysis when an app passes it through `Encode.to_bytes` (e.g. to log
## or serialize the chosen algorithm). The workaround is to accept a `Str`
## at the platform boundary.
##
## TODO: Use tags when switching to Roc 0.1+.
##
## ```roc
## digest = Crypto.hash!(Str.to_utf8("hello"), "SHA-256")
## # "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
## ```
hash! : List U8, Str => Str
hash! = |bytes, algorithm|
    Host.hash!(bytes, algorithm)

## Hash a file by path and return the lowercase-hex digest. Reads the whole
## file into memory.
##
## See [hash!] for the supported `algorithm` values.
##
## ```roc
## digest = Crypto.hash_file!("path/to/file.zip", "SHA-256")?
## ```
hash_file! : Str, Str => Result Str [FileReadErr Path IOErr]
hash_file! = |path, algorithm|
    bytes = File.read_bytes!(path)?
    Ok(hash!(bytes, algorithm))

## Decrypt a ciphertext encrypted with AES256-GCM.
##
## Parameters:
## - `ciphertext`: The encrypted data (without nonce or auth tag)
## - `key`: Must be exactly 32 bytes for AES-256
## - `nonce`: Must be exactly 12 bytes (the same nonce used during encryption)
## - `auth_tag`: Must be exactly 16 bytes (returned by encrypt_aes256_gcm!)
decrypt_aes256_gcm! : { ciphertext : List U8, key : List U8, nonce: List U8, auth_tag : List U8 } => Result (List U8) Str
decrypt_aes256_gcm! = |{ ciphertext, key, nonce, auth_tag }|
  Host.decrypt_aes256_gcm!(
    ciphertext,
    key,
    nonce,
    auth_tag,
  )

## Encrypt plaintext with AES256-GCM.
## Returns both the ciphertext and the authentication tag.
##
## **Critical**: Never reuse a nonce with the same key. Reusing a (key, nonce) pair
## completely breaks AES-GCM's security, allowing attackers to decrypt messages and
## forge valid ciphertexts. For most applications, generate a random 12-byte nonce
## via `random_bytes!` for each encryption and prepend it to the ciphertext.
##
## Parameters:
## - `plaintext`: The data to encrypt
## - `key`: Must be exactly 32 bytes for AES-256
## - `nonce`: Must be exactly 12 bytes and unique per encryption with the same key
encrypt_aes256_gcm! : { plaintext : List U8, key : List U8, nonce: List U8 } => Result { ciphertext : List U8, auth_tag : List U8 } Str
encrypt_aes256_gcm! = |{ plaintext, key, nonce }|
  Host.encrypt_aes256_gcm!(plaintext, key, nonce)

## Derive a cryptographic key from a password using PBKDF2-HMAC-SHA256.
##
## PBKDF2 repeatedly applies HMAC-SHA256 to derive a key of specified length.
## The iteration count makes brute-force attacks computationally expensive.
##
## Parameters:
## - `password`: The password or secret to derive a key from
## - `salt`: A unique salt (use `random_bytes!` to generate, minimum 16 bytes recommended)
## - `iterations`: Number of iterations (higher = slower but more secure)
## - `key_length`: Desired output key length in bytes
##
## Security recommendations:
## - **Iterations**: OWASP recommends 600,000+ for PBKDF2-HMAC-SHA256 (as of 2023).
##   Values below 10,000 offer minimal protection against brute-force attacks.
## - **Salt**: Use at least 16 bytes from `random_bytes!`. Never reuse salts.
## - **Key length**: Typically 32 bytes for AES-256, 64 bytes for HMAC-SHA512.
##
## Common use cases:
## - Deriving encryption keys from user passwords
## - Converting text secrets into fixed-length cryptographic keys
pbkdf2_hmac_sha256! : { password : List U8, salt : List U8, iterations: U32, key_length: U32 } => List U8
pbkdf2_hmac_sha256! = |{password, salt, iterations, key_length}| Host.pbkdf2_hmac_sha256!(
    password,
    salt,
    iterations,
    key_length,
  )

## Generate cryptographically secure random bytes.
random_bytes! : U32 => Result (List U8) Str
random_bytes! = |length|
  Host.random_bytes!(length)

## Hash a password using bcrypt.
##
## Returns the hash as a string in the standard bcrypt format (`$2b$cost$...`),
## which can be stored directly in a database and passed to `bcrypt_verify!`.
##
## Parameters:
## - `password`: The password to hash
## - `cost`: Work factor between 4 and 31 (inclusive). Each increment doubles computation time.
##
## Security recommendations:
## - Cost 10: ~100ms on modern hardware (minimum for production)
## - Cost 12: ~400ms (good default for most applications)
## - Cost 14: ~1.6s (high security)
## - Values below 10 are generally considered insufficient for password storage.
bcrypt_hash! : List U8, U32 => Result Str Str
bcrypt_hash! = |password, cost|
  Host.bcrypt_hash!(password, cost)

## Verify a password against a bcrypt hash.
## Returns Ok(Bool.true) if the password matches, Ok(Bool.false) if it doesn't,
## or Err if there's an issue with the hash format.
bcrypt_verify! : List U8, Str => Result Bool Str
bcrypt_verify! = |password, hash|
  Host.bcrypt_verify!(password, hash)
