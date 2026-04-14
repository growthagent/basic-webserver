app [Model, init!, respond!] {
    pf: platform "../platform/main.roc",
}

import pf.Stdout
import pf.Crypto
import pf.File
import pf.Http exposing [Request, Response]

# Tests Crypto module functions: hash!, hash_file!, hash_file_chunks!.
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
    Stdout.line!("Testing Crypto.hash!, hash_file!, hash_file_chunks!...")?

    test_hash!({})?
    test_hash_file!({})?
    test_hash_file_chunks!({})?

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
        Crypto.hash!([], Sha1),
    )?
    Stdout.line!("✓ SHA-1 of empty input matches RFC 3174")?

    # SHA-1 of "abc" (RFC 3174 test vector)
    expect_eq(
        "hash! SHA-1 of \"abc\"",
        "a9993e364706816aba3e25717850c26c9cd0d89d",
        Crypto.hash!(Str.to_utf8("abc"), Sha1),
    )?
    Stdout.line!("✓ SHA-1 of \"abc\" matches RFC 3174")?

    # SHA-256 of "abc" (NIST test vector)
    expect_eq(
        "hash! SHA-256 of \"abc\"",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        Crypto.hash!(Str.to_utf8("abc"), Sha256),
    )?
    Stdout.line!("✓ SHA-256 of \"abc\" matches NIST")?

    # SHA-512 of empty string (NIST)
    expect_eq(
        "hash! SHA-512 of empty",
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        Crypto.hash!([], Sha512),
    )?
    Stdout.line!("✓ SHA-512 of empty input matches NIST")?

    # SHA-384 of "abc" (NIST test vector)
    expect_eq(
        "hash! SHA-384 of \"abc\"",
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
        Crypto.hash!(Str.to_utf8("abc"), Sha384),
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
        Crypto.hash!(utf8_bytes, Sha1),
    )?
    expect_eq(
        "hash! SHA-256 of UTF-8 \"héllo wörld\"",
        "a1003f7d04a4115711d0b48a2eaf1359ce565d2d2a6fd65098dfcffadeeef59f",
        Crypto.hash!(utf8_bytes, Sha256),
    )?
    Stdout.line!("✓ Multi-byte UTF-8 hashes correctly (SHA-1 + SHA-256)")?

    # Determinism: same input → same output
    a = Crypto.hash!(Str.to_utf8("hello world"), Sha1)
    b = Crypto.hash!(Str.to_utf8("hello world"), Sha1)
    if a != b then
        Err(FailedExpectation("hash! not deterministic"))?
    else
        {}
    Stdout.line!("✓ Deterministic")

test_hash_file! : {} => Result {} _
test_hash_file! = |{}|
    Stdout.line!("\nTesting Crypto.hash_file!:")?

    # Idempotency: ensure no leftover temp files from a prior failed run.
    test_path = "tests/test_crypto_hash_file.tmp"
    empty_path = "tests/test_crypto_hash_empty.tmp"
    File.delete!(test_path) |> Result.with_default({})
    File.delete!(empty_path) |> Result.with_default({})

    # Write a known file and hash it with all 4 algorithms.
    File.write_bytes!(Str.to_utf8("abc"), test_path)
        |> Result.map_err(|e| FailedExpectation("Could not write test file: ${Inspect.to_str(e)}"))?

    sha1 = Crypto.hash_file!(test_path, Sha1)
        |> Result.map_err(|e| FailedExpectation("hash_file! SHA-1 failed: ${e}"))?
    expect_eq("hash_file! SHA-1 of \"abc\"", "a9993e364706816aba3e25717850c26c9cd0d89d", sha1)?
    Stdout.line!("✓ SHA-1 of file containing \"abc\" matches RFC 3174")?

    sha256 = Crypto.hash_file!(test_path, Sha256)
        |> Result.map_err(|e| FailedExpectation("hash_file! SHA-256 failed: ${e}"))?
    expect_eq("hash_file! SHA-256 of \"abc\"", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", sha256)?
    Stdout.line!("✓ SHA-256 of file matches NIST")?

    sha384 = Crypto.hash_file!(test_path, Sha384)
        |> Result.map_err(|e| FailedExpectation("hash_file! SHA-384 failed: ${e}"))?
    expect_eq("hash_file! SHA-384 of \"abc\"", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7", sha384)?
    Stdout.line!("✓ SHA-384 of file matches NIST")?

    sha512 = Crypto.hash_file!(test_path, Sha512)
        |> Result.map_err(|e| FailedExpectation("hash_file! SHA-512 failed: ${e}"))?
    expect_eq("hash_file! SHA-512 of \"abc\"", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", sha512)?
    Stdout.line!("✓ SHA-512 of file matches NIST")?

    # Cross-check: hash!(bytes) and hash_file!(file with same bytes) must agree
    # for every algorithm. This catches a class of bugs where one path is broken
    # but happens to match a hardcoded test vector that's also wrong.
    abc_bytes = Str.to_utf8("abc")
    expect_eq("cross-check SHA-1", Crypto.hash!(abc_bytes, Sha1), sha1)?
    expect_eq("cross-check SHA-256", Crypto.hash!(abc_bytes, Sha256), sha256)?
    expect_eq("cross-check SHA-384", Crypto.hash!(abc_bytes, Sha384), sha384)?
    expect_eq("cross-check SHA-512", Crypto.hash!(abc_bytes, Sha512), sha512)?
    Stdout.line!("✓ hash! and hash_file! agree for all 4 algorithms")?

    # Empty file
    File.write_bytes!([], empty_path)
        |> Result.map_err(|e| FailedExpectation("Could not write empty file: ${Inspect.to_str(e)}"))?
    sha1_empty = Crypto.hash_file!(empty_path, Sha1)
        |> Result.map_err(|e| FailedExpectation("hash_file! empty failed: ${e}"))?
    expect_eq("hash_file! SHA-1 of empty", "da39a3ee5e6b4b0d3255bfef95601890afd80709", sha1_empty)?
    Stdout.line!("✓ SHA-1 of empty file matches RFC 3174")?

    # Missing file → error. The directory itself doesn't exist either, so this
    # path is guaranteed-absent regardless of any leftover state.
    when Crypto.hash_file!("tests/nonexistent_dir/missing.tmp", Sha1) is
        Err(_) -> Stdout.line!("✓ Missing file returns Err")?
        Ok(_) -> Err(FailedExpectation("hash_file! should fail on missing file"))?

    File.delete!(test_path) |> Result.with_default({})
    File.delete!(empty_path) |> Result.with_default({})
    Ok({})

test_hash_file_chunks! : {} => Result {} _
test_hash_file_chunks! = |{}|
    Stdout.line!("\nTesting Crypto.hash_file_chunks!:")?

    # Idempotency: ensure no leftover temp files from a prior failed run.
    abc_path = "tests/test_crypto_chunks_abc.tmp"
    empty_path = "tests/test_crypto_chunks_empty.tmp"
    boundary_path = "tests/test_crypto_chunks_boundary.tmp"
    over_path = "tests/test_crypto_chunks_over.tmp"
    big_path = "tests/test_crypto_chunks_big.tmp"
    File.delete!(abc_path) |> Result.with_default({})
    File.delete!(empty_path) |> Result.with_default({})
    File.delete!(boundary_path) |> Result.with_default({})
    File.delete!(over_path) |> Result.with_default({})
    File.delete!(big_path) |> Result.with_default({})

    # ── SHA-1 reference: "abc" with 1-byte chunks ───────────────────────────
    # Algorithm: SHA1 each chunk, concatenate raw 20-byte digests, SHA1 the result.
    # SHA1(SHA1("a") || SHA1("b") || SHA1("c")) = 24ba5eeff007db49a25c68779c503992561ab37f
    # Computed independently via openssl.
    File.write_bytes!(Str.to_utf8("abc"), abc_path)
        |> Result.map_err(|e| FailedExpectation("Could not write file: ${Inspect.to_str(e)}"))?

    chunks_1byte = Crypto.hash_file_chunks!(abc_path, { algorithm: Sha1, chunk_size_bytes: 1 })
        |> Result.map_err(|e| FailedExpectation("hash_file_chunks! failed: ${e}"))?
    expect_eq("hash_file_chunks! \"abc\" SHA-1 chunk=1", "24ba5eeff007db49a25c68779c503992561ab37f", chunks_1byte)?
    Stdout.line!("✓ 1-byte chunks match reference")?

    # Single-chunk case: chunk_size > file_size → SHA1(SHA1("abc"))
    chunks_big = Crypto.hash_file_chunks!(abc_path, { algorithm: Sha1, chunk_size_bytes: 1000 })
        |> Result.map_err(|e| FailedExpectation("hash_file_chunks! big chunk failed: ${e}"))?
    expect_eq("hash_file_chunks! \"abc\" SHA-1 chunk=1000", "0d3ced9bec10a777aec23ccc353a8c08a633045e", chunks_big)?
    Stdout.line!("✓ Single-chunk case works")?

    # ── chunk_size_bytes = 0 → clamped to 1 (matches joy frontend) ──────────
    chunks_zero = Crypto.hash_file_chunks!(abc_path, { algorithm: Sha1, chunk_size_bytes: 0 })
        |> Result.map_err(|e| FailedExpectation("hash_file_chunks! chunk_size=0 failed: ${e}"))?
    expect_eq(
        "hash_file_chunks! chunk_size=0 must equal chunk_size=1 (clamped)",
        chunks_1byte,
        chunks_zero,
    )?
    Stdout.line!("✓ chunk_size_bytes=0 is clamped to 1 (matches joy)")?

    # ── SHA-256 chunked: "abcdef" 3-byte chunks (verifies algorithm dispatch) ─
    # Computed independently via openssl:
    #   SHA256(SHA256("abc") || SHA256("def")) =
    #   9c04d30057b754af1b2d2d4f5675782dd61a5a659c34ee6c2af47526b66cafa6
    File.write_bytes!(Str.to_utf8("abcdef"), boundary_path)
        |> Result.map_err(|e| FailedExpectation("Could not write boundary file: ${Inspect.to_str(e)}"))?

    chunks_sha256 = Crypto.hash_file_chunks!(boundary_path, { algorithm: Sha256, chunk_size_bytes: 3 })
        |> Result.map_err(|e| FailedExpectation("hash_file_chunks! SHA-256 failed: ${e}"))?
    expect_eq(
        "hash_file_chunks! \"abcdef\" SHA-256 chunk=3",
        "9c04d30057b754af1b2d2d4f5675782dd61a5a659c34ee6c2af47526b66cafa6",
        chunks_sha256,
    )?
    Stdout.line!("✓ SHA-256 chunked hash works (verifies algorithm dispatch in chunk path)")?

    # Empty file → SHA1 of empty bytes
    File.write_bytes!([], empty_path)
        |> Result.map_err(|e| FailedExpectation("Could not write empty file: ${Inspect.to_str(e)}"))?
    chunks_empty = Crypto.hash_file_chunks!(empty_path, { algorithm: Sha1, chunk_size_bytes: 16 })
        |> Result.map_err(|e| FailedExpectation("hash_file_chunks! empty failed: ${e}"))?
    expect_eq("hash_file_chunks! empty file SHA-1", "da39a3ee5e6b4b0d3255bfef95601890afd80709", chunks_empty)?
    Stdout.line!("✓ Empty file → SHA-1 of empty input")?

    # Exact chunk boundary: 6-byte file with 3-byte chunks → 2 chunks ("abc","def")
    chunks_boundary = Crypto.hash_file_chunks!(boundary_path, { algorithm: Sha1, chunk_size_bytes: 3 })
        |> Result.map_err(|e| FailedExpectation("hash_file_chunks! boundary failed: ${e}"))?
    expect_eq("hash_file_chunks! exact boundary 6/3", "18a55436ce198b1412df9fa91896524ce4173053", chunks_boundary)?
    Stdout.line!("✓ Exact chunk boundary works")?

    # Boundary + 1: 7-byte file with 3-byte chunks → 2 full + 1 partial ("abc","def","g")
    File.write_bytes!(Str.to_utf8("abcdefg"), over_path)
        |> Result.map_err(|e| FailedExpectation("Could not write over file: ${Inspect.to_str(e)}"))?
    chunks_over = Crypto.hash_file_chunks!(over_path, { algorithm: Sha1, chunk_size_bytes: 3 })
        |> Result.map_err(|e| FailedExpectation("hash_file_chunks! over failed: ${e}"))?
    expect_eq("hash_file_chunks! partial last chunk 7/3", "e05707a95333c72b31bb66e6a8bed63dd254649a", chunks_over)?
    Stdout.line!("✓ Partial last chunk works")?

    # ── Streaming test: 100 distinct 1024-byte blocks ──────────────────────
    # Exercises the read loop 100 times with VARIED data so each chunk is
    # distinguishable. Block i (0-indexed) is 1024 copies of byte (i+1), so
    # offset-tracking bugs and buffer-reuse bugs would change the final hash.
    # Uniform data (like 100 KB of zeros) would NOT catch these bugs because
    # every chunk would hash identically.
    #
    # Reference computed independently via openssl on the same byte sequence:
    #   awk 'BEGIN { for (i=1; i<=100; i++) for (j=0; j<1024; j++) printf "%c", i }' > varied.bin
    #   for c in $(seq 0 99); do
    #     dd if=varied.bin bs=1024 count=1 skip=$c status=none | openssl dgst -sha1 -binary
    #   done > concat.bin
    #   openssl dgst -sha1 concat.bin
    # → 324c11a8fb079d649d66774a73a965a2cc30405d
    big_data =
        List.range({ start: At(1u8), end: At(100u8) })
        |> List.map(|n| List.repeat(n, 1024))
        |> List.join
    File.write_bytes!(big_data, big_path)
        |> Result.map_err(|e| FailedExpectation("Could not write big file: ${Inspect.to_str(e)}"))?

    chunks_streaming = Crypto.hash_file_chunks!(big_path, { algorithm: Sha1, chunk_size_bytes: 1024 })
        |> Result.map_err(|e| FailedExpectation("hash_file_chunks! streaming failed: ${e}"))?
    expect_eq(
        "hash_file_chunks! 100 distinct 1024-byte blocks SHA-1 chunk=1024",
        "324c11a8fb079d649d66774a73a965a2cc30405d",
        chunks_streaming,
    )?
    Stdout.line!("✓ 100 distinct chunks streaming hash matches reference")?

    # Missing file → error. Directory itself doesn't exist.
    when Crypto.hash_file_chunks!("tests/nonexistent_dir/missing.tmp", { algorithm: Sha1, chunk_size_bytes: 16 }) is
        Err(_) -> Stdout.line!("✓ Missing file returns Err")?
        Ok(_) -> Err(FailedExpectation("hash_file_chunks! should fail on missing file"))?

    File.delete!(abc_path) |> Result.with_default({})
    File.delete!(empty_path) |> Result.with_default({})
    File.delete!(boundary_path) |> Result.with_default({})
    File.delete!(over_path) |> Result.with_default({})
    File.delete!(big_path) |> Result.with_default({})
    Ok({})

respond! : Request, Model => Result Response [ServerErr Str]_
respond! = |_, _|
    Ok({ status: 200, headers: [], body: Str.to_utf8("crypto tests") })
