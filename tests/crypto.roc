app [Model, init!, respond!] {
    pf: platform "../platform/main.roc",
}

import pf.Stdout
import pf.Crypto
import pf.File
import pf.Http exposing [Request, Response]

# Tests Crypto module functions: hash!, hash_file!.
# Other Crypto functions are tested in basic-cli's tests/crypto.roc and the
# Rust implementation is shared via cargo, so we don't duplicate those tests
# here — we just verify the new hash functions are wired up correctly through
# basic-webserver's host.

Model : {}

init! : {} => Result Model _
init! = |{}|
    when run_tests!({}) is
        Ok(_) -> Err(Exit(0, "Ran all tests."))
        Err(err) -> Err(Exit(1, "Test run failed:\n\t${Inspect.to_str(err)}"))

run_tests! : {} => Result {} _
run_tests! = |{}|
    Stdout.line!("Testing Crypto.hash!, hash_file!...")?

    test_hash!({})?
    test_hash_file!({})?

    Stdout.line!("\nAll crypto tests passed.")

expect_eq : Str, Str, Str -> Result {} [FailedExpectation Str]
expect_eq = |label, expected, actual|
    if expected != actual then
        Err(FailedExpectation(
            """
            ${label}:
            - Expected: ${expected}
            - Got: ${actual}
            """
        ))
    else
        Ok({})

test_hash! : {} => Result {} _
test_hash! = |{}|
    Stdout.line!("\nTesting Crypto.hash!:")?

    # SHA-1 of empty string (RFC 3174)
    expect_eq(
        "hash! SHA-1 of empty",
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        Crypto.hash!([], "SHA-1"),
    )?
    Stdout.line!("✓ SHA-1 of empty input matches RFC 3174")?

    # SHA-1 of "abc" (RFC 3174 test vector)
    expect_eq(
        "hash! SHA-1 of \"abc\"",
        "a9993e364706816aba3e25717850c26c9cd0d89d",
        Crypto.hash!(Str.to_utf8("abc"), "SHA-1"),
    )?
    Stdout.line!("✓ SHA-1 of \"abc\" matches RFC 3174")?

    # SHA-256 of "abc" (NIST test vector)
    expect_eq(
        "hash! SHA-256 of \"abc\"",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        Crypto.hash!(Str.to_utf8("abc"), "SHA-256"),
    )?
    Stdout.line!("✓ SHA-256 of \"abc\" matches NIST")?

    # SHA-512 of empty string (NIST)
    expect_eq(
        "hash! SHA-512 of empty",
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        Crypto.hash!([], "SHA-512"),
    )?
    Stdout.line!("✓ SHA-512 of empty input matches NIST")?

    # SHA-384 of "abc" (NIST test vector)
    expect_eq(
        "hash! SHA-384 of \"abc\"",
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
        Crypto.hash!(Str.to_utf8("abc"), "SHA-384"),
    )?
    Stdout.line!("✓ SHA-384 of \"abc\" matches NIST")?

    # Multi-byte UTF-8: "héllo wörld" — sanity check that Str→bytes→hash
    # is wired correctly end-to-end. The UTF-8 encoding of this string is
    # 13 bytes (not 11), so any byte/char confusion would give a different hash.
    # Reference values computed independently via openssl.
    utf8_bytes = Str.to_utf8("héllo wörld")
    expect_eq(
        "hash! SHA-1 of UTF-8 \"héllo wörld\"",
        "24e9f5c07847ff8a2a9fa77456655792f5bc7f9f",
        Crypto.hash!(utf8_bytes, "SHA-1"),
    )?
    expect_eq(
        "hash! SHA-256 of UTF-8 \"héllo wörld\"",
        "a1003f7d04a4115711d0b48a2eaf1359ce565d2d2a6fd65098dfcffadeeef59f",
        Crypto.hash!(utf8_bytes, "SHA-256"),
    )?
    Stdout.line!("✓ Multi-byte UTF-8 hashes correctly (SHA-1 + SHA-256)")?

    # Determinism: same input → same output
    a = Crypto.hash!(Str.to_utf8("hello world"), "SHA-1")
    b = Crypto.hash!(Str.to_utf8("hello world"), "SHA-1")
    if a != b then
        Err(FailedExpectation("hash! not deterministic"))?
    else
        {}
    Stdout.line!("✓ Deterministic")

test_hash_file! : {} => Result {} _
test_hash_file! = |{}|
    Stdout.line!("\nTesting Crypto.hash_file!:")?

    # Idempotency: ensure no leftover temp files from a prior failed run.
    test_path = "test_crypto_hash_file.tmp"
    empty_path = "test_crypto_hash_empty.tmp"
    File.delete!(test_path) |> Result.with_default({})
    File.delete!(empty_path) |> Result.with_default({})

    # Write a known file and hash it with all 4 algorithms.
    File.write_bytes!(Str.to_utf8("abc"), test_path)
        |> Result.map_err(|e| FailedExpectation("Could not write test file: ${Inspect.to_str(e)}"))?

    sha1 = Crypto.hash_file!(test_path, "SHA-1")
        |> Result.map_err(|e| FailedExpectation("hash_file! SHA-1 failed: ${Inspect.to_str(e)}"))?
    expect_eq("hash_file! SHA-1 of \"abc\"", "a9993e364706816aba3e25717850c26c9cd0d89d", sha1)?
    Stdout.line!("✓ SHA-1 of file containing \"abc\" matches RFC 3174")?

    sha256 = Crypto.hash_file!(test_path, "SHA-256")
        |> Result.map_err(|e| FailedExpectation("hash_file! SHA-256 failed: ${Inspect.to_str(e)}"))?
    expect_eq("hash_file! SHA-256 of \"abc\"", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", sha256)?
    Stdout.line!("✓ SHA-256 of file matches NIST")?

    sha384 = Crypto.hash_file!(test_path, "SHA-384")
        |> Result.map_err(|e| FailedExpectation("hash_file! SHA-384 failed: ${Inspect.to_str(e)}"))?
    expect_eq("hash_file! SHA-384 of \"abc\"", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7", sha384)?
    Stdout.line!("✓ SHA-384 of file matches NIST")?

    sha512 = Crypto.hash_file!(test_path, "SHA-512")
        |> Result.map_err(|e| FailedExpectation("hash_file! SHA-512 failed: ${Inspect.to_str(e)}"))?
    expect_eq("hash_file! SHA-512 of \"abc\"", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", sha512)?
    Stdout.line!("✓ SHA-512 of file matches NIST")?

    # Cross-check: hash!(bytes) and hash_file!(file with same bytes) must agree
    # for every algorithm. This catches a class of bugs where one path is broken
    # but happens to match a hardcoded test vector that's also wrong.
    abc_bytes = Str.to_utf8("abc")
    expect_eq("cross-check SHA-1", Crypto.hash!(abc_bytes, "SHA-1"), sha1)?
    expect_eq("cross-check SHA-256", Crypto.hash!(abc_bytes, "SHA-256"), sha256)?
    expect_eq("cross-check SHA-384", Crypto.hash!(abc_bytes, "SHA-384"), sha384)?
    expect_eq("cross-check SHA-512", Crypto.hash!(abc_bytes, "SHA-512"), sha512)?
    Stdout.line!("✓ hash! and hash_file! agree for all 4 algorithms")?

    # Empty file
    File.write_bytes!([], empty_path)
        |> Result.map_err(|e| FailedExpectation("Could not write empty file: ${Inspect.to_str(e)}"))?
    sha1_empty = Crypto.hash_file!(empty_path, "SHA-1")
        |> Result.map_err(|e| FailedExpectation("hash_file! empty failed: ${Inspect.to_str(e)}"))?
    expect_eq("hash_file! SHA-1 of empty", "da39a3ee5e6b4b0d3255bfef95601890afd80709", sha1_empty)?
    Stdout.line!("✓ SHA-1 of empty file matches RFC 3174")?

    # Missing file → error. The directory itself doesn't exist either, so this
    # path is guaranteed-absent regardless of any leftover state.
    when Crypto.hash_file!("nonexistent_dir/missing.tmp", "SHA-1") is
        Err(_) -> Stdout.line!("✓ Missing file returns Err")?
        Ok(_) -> Err(FailedExpectation("hash_file! should fail on missing file"))?

    File.delete!(test_path) |> Result.with_default({})
    File.delete!(empty_path) |> Result.with_default({})
    Ok({})

respond! : Request, Model => Result Response [ServerErr Str]_
respond! = |_, _|
    Ok({ status: 200, headers: [], body: Str.to_utf8("crypto tests") })
