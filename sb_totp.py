# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Copyright 2024 Sam Blenny
#
# Related RFCs:
# - [RFC 4226: HOTP](https://datatracker.ietf.org/doc/html/rfc4226)
# - [RFC 6238: TOTP](https://datatracker.ietf.org/doc/html/rfc6238)
#
import struct

from sb_hmac import hmac_sha1


def normalize_base32(s):
    # Normalize a Base32 secret string from a TOTP URI.
    # This is meant to handle known TOTP "secret=..." query parameter quirks.
    # - Converts URL-encoded padding (%3D / %3d) to '='
    # - Strips whitespace
    # - Uppercases all letters
    #
    return s.strip().replace("%3D", "=").replace("%3d", "=").upper()


def parse_uri(uri):
    # Parse a TOTP QR code URI and extract the Base32 secret, validating that
    # algorithm=SHA1, digits=6, period=30
    # - Returns: Normalized Base32 secret string
    # - Raises: ValueError if the URI is malformed or parameters do not match
    #           expected values

    # 1. Validate scheme
    if not uri.startswith("otpauth://totp/"):
        raise ValueError("Invalid scheme or method (expected otpauth://totp/)")

    # 2. Split label and query
    try:
        _, query = uri.split("?", 1)
    except ValueError:
        raise ValueError("URI missing query string")

    # 3. Parse query manually
    params = {}
    for pair in query.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            params[k] = v

    # 4. Extract secret and normalize it
    secret = params.get("secret")
    if not secret:
        raise ValueError("Missing secret")
    secret = normalize_base32(secret)  # handles padding, uppercasing, etc

    # 5. Extract and validate other fields
    algorithm = params.get("algorithm", "SHA1")
    digits = params.get("digits", "6")
    period = params.get("period", "30")

    if algorithm.upper() != "SHA1":
        raise ValueError("Unsupported algorithm (expected SHA1)")
    if digits != "6":
        raise ValueError("Unsupported digits (expected 6)")
    if period != "30":
        raise ValueError("Unsupported period (expected 30)")

    return secret


def base32_encode(data):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    # Ensure the input is bytes
    if isinstance(data, str):
        data = data.encode('utf-8')

    # Add padding to make the data length a multiple of 5 bytes
    unpadded_len = len(data)
    padding = (5 - unpadded_len % 5) % 5
    data_padded = data + b'\x00' * padding

    # Create the encoded string by processing every 5 bytes
    encoded = []
    def append(bits):
        encoded.append(alphabet[bits])

    for i in range(0, len(data), 5):
        (a, b, c, d, e) = data_padded[i:i+5]
        last_iteration = bool(i+5 > unpadded_len)

        # For each chunk of 5 bytes, extract 5-bit groups
        append(  a >> 3)
        append((((a << 5) & 0xFF) >> 3) | (b >> 6))
        if last_iteration and padding == 4:
            encoded.append("======")
            break
        append((((b << 2) & 0xFF) >> 3))
        append((((b << 7) & 0xFF) >> 3) | (c >> 4))
        if last_iteration and padding == 3:
            encoded.append("====")
            break
        append((((c << 4) & 0xFF) >> 3) | (d >> 7))
        if last_iteration and padding == 2:
            encoded.append("===")
            break
        append( ((d << 1) & 0xFF) >> 3)
        append((((d << 6) & 0xFF) >> 3) | (e >> 5))
        if last_iteration and padding == 1:
            encoded.append("=")
            break
        append( ((e << 3) & 0xFF) >> 3)

    # Join the characters and remove the padding
    return ''.join(encoded)


def base32_decode(s):
    # Decode a Base32 string to bytes (ignores '=' and is case-insensitive)
    # CircuitPython doesn't appear to have this either built in or in a library
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    s = s.strip().replace("=", "").upper()
    bits = 0
    bit_buffer = 0
    result = bytearray()

    for c in s:
        if c not in alphabet:
            raise ValueError("Invalid Base32 character: " + c)
        val = alphabet.index(c)
        bit_buffer = (bit_buffer << 5) | val
        bits += 5
        while bits >= 8:
            bits -= 8
            byte = (bit_buffer >> bits) & 0xff
            result.append(byte)

    return bytes(result)


def totp_sha1(secret_b32, timestamp, digits=6, period=30):
    # Return a string with the TOTP code for the given Unix timestamp. The
    # configurable timestamp is meant to support tests that check for the text
    # vectors from RFC6238 Appendix B.

    key =  base32_decode(secret_b32)

    counter = timestamp // period
    msg = struct.pack(">Q", counter)  # hash timestamp as big-endian int64

    hash_ = hmac_sha1(key, msg)

    # Do the dynamic truncation thing from RFC 6238 Appendix A
    offset = hash_[len(hash_)-1] & 0x0F
    # Extract the 31-bit integer following sample code in Appendix A
    binary = ((hash_[offset] & 0x7f) << 24 |
            (hash_[offset+1] & 0xff) << 16 |
            (hash_[offset+2] & 0xff) << 8 |
            (hash_[offset+3] & 0xff))

    # Do modulo (10^digits) so the final code is the right number of digits
    binary = str(binary % (10 ** digits))
    return ("0" * max(0, digits - len(binary))) + binary  # zero fill on left


# ------------------------------------------------------
# Tests
#
# >>> import sb_totp
# >>> sb_totp.test_totp_edge_cases()
# Running TOTP edge-case tests...
#
# RFC 6238 SHA1 tests:
# t=59 expected=94287082 got=94287082 OK
# t=1111111109 expected=07081804 got=07081804 OK
# t=1111111111 expected=14050471 got=14050471 OK
# t=1234567890 expected=89005924 got=89005924 OK
# t=2000000000 expected=69279037 got=69279037 OK
# t=20000000000 expected=65353130 got=65353130 OK
#
# RFC 2202 HMAC-SHA1 tests:
# Test 0: OK
# Test 1: OK
#
# Weird-but-valid Base32 secrets:
# AA -> OK (1 bytes)
# AE -> OK (1 bytes)
# AI -> OK (1 bytes)
# AM -> OK (1 bytes)
# AQ -> OK (1 bytes)
# AU -> OK (1 bytes)
# AY -> OK (1 bytes)
# A4====== -> OK (1 bytes)
# ABCDEFGHAA -> OK (6 bytes)
# ABAA==== -> OK (2 bytes)
# ACAA==== -> OK (2 bytes)
# ABCD%3D -> OK (2 bytes)
# EFGH%3d -> OK (2 bytes)
# Lowercase secret -> OK
#
# RFC 4648 Base32 test vectors (encode direction):
# t= expected='' got='' OK
# t=f expected='MY======' got='MY======' OK
# t=fo expected='MZXQ====' got='MZXQ====' OK
# t=foo expected='MZXW6===' got='MZXW6===' OK
# t=foob expected='MZXW6YQ=' got='MZXW6YQ=' OK
# t=fooba expected='MZXW6YTB' got='MZXW6YTB' OK
# t=foobar expected='MZXW6YTBOI======' got='MZXW6YTBOI======' OK
#
# RFC 4648 Base32 test vectors (decode direction):
# t= expected='' got='b''' OK
# t=f expected='f' got='b'f'' OK
# t=fo expected='fo' got='b'fo'' OK
# t=foo expected='foo' got='b'foo'' OK
# t=foob expected='foob' got='b'foob'' OK
# t=fooba expected='fooba' got='b'fooba'' OK
# t=foobar expected='foobar' got='b'foobar'' OK
#
# Round-Trip Base32 encode/decode tests:
# Test 0 - Round-trip: OK (input: b'hello', encoded: NBSWY3DP, decoded: b'hello')
# Test 1 - Round-trip: OK (input: b'1234567890', encoded: GEZDGNBVGY3TQOJQ, decoded: b'1234567890')
# Test 2 - Round-trip: OK (input: b'\x00\x01\x02\x03\x04\x05', encoded: AAAQEAYEAU======, decoded: b'\x00\x01\x02\x03\x04\x05')
# Test 3 - Round-trip: OK (input: b'ABCDEF1234567890', encoded: IFBEGRCFIYYTEMZUGU3DOOBZGA======, decoded: b'ABCDEF1234567890')
# Test 4 - Round-trip: OK (input: b'abcdefghijklmnopqrstuvwxyz', encoded: MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43UOV3HO6DZPI======, decoded: b'abcdefghijklmnopqrstuvwxyz')
# >>>
# ------------------------------------------------------

def test_totp_edge_cases():
    print("Running TOTP edge-case tests...")

    # ------------------------------------------------------
    # 1. RFC 6238 SHA1 TOTP vectors
    # ------------------------------------------------------

    # RFC 6238 secret: "12345678901234567890"
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    test_times = [
        59,
        1111111109,
        1111111111,
        1234567890,
        2000000000,
        20000000000,
    ]
    expected_totps = [
        "94287082",
        "07081804",
        "14050471",
        "89005924",
        "69279037",
        "65353130",
    ]
    print("\nRFC 6238 SHA1 tests:")
    for t, exp in zip(test_times, expected_totps):
        got = totp_sha1(secret, t, digits=8)
        print(f"t={t} expected={exp} got={got}", "OK" if got == exp else "FAIL")

    # ------------------------------------------------------
    # 2. HMAC-SHA1 tests (RFC 2202)
    # ------------------------------------------------------
    print("\nRFC 2202 HMAC-SHA1 tests:")
    test_cases = [
        (bytes([0x0b]*20), b"Hi There",
         bytes([0xb6,0x17,0x31,0x86,0x55,0x05,0x72,0x64,
                0xe2,0x8b,0xc0,0xb6,0xfb,0x37,0x8c,0x8e,
                0xf1,0x46,0xbe,0x00])),
        (b"Jefe", b"what do ya want for nothing?",
         bytes([0xef,0xfc,0xdf,0x6a,0xe5,0xeb,0x2f,0xa2,
                0xd2,0x74,0x16,0xd5,0xf1,0x84,0xdf,0x9c,
                0x25,0x9a,0x7c,0x79])),
    ]
    for i, (key, data, expected) in enumerate(test_cases):
        got = hmac_sha1(key, data)
        print(f"Test {i}:", "OK" if got == expected else "FAIL")

    # ------------------------------------------------------
    # 3. Weird-but-valid Base32 secrets
    # ------------------------------------------------------
    print("\nWeird-but-valid Base32 secrets:")
    secrets = [
        "AA", "AE", "AI", "AM", "AQ", "AU", "AY",
        "A4======", "ABCDEFGHAA", "ABAA====", "ACAA====",
        "ABCD%3D", "EFGH%3d"  # URL-encoded padding
    ]
    for s in secrets:
        try:
            decoded = base32_decode(normalize_base32(s))
            print(f"{s} -> OK ({len(decoded)} bytes)")
        except Exception as e:
            print(f"{s} -> FAIL ({e})")

    # Lowercase secret test
    try:
        decoded = base32_decode("jbswy3dpehpk3pxp")
        print("Lowercase secret -> OK")
    except Exception as e:
        print("Lowercase secret -> FAIL", e)


    # ------------------------------------------------------
    # 4. Base32 encode with RFC 4648 test vectors
    # ------------------------------------------------------
    test_data = [
        "",
        "f",
        "fo",
        "foo",
        "foob",
        "fooba",
        "foobar",
    ]
    base32_string = [
        "",
        "MY======",
        "MZXQ====",
        "MZXW6===",
        "MZXW6YQ=",
        "MZXW6YTB",
        "MZXW6YTBOI======"
    ]
    print("\nRFC 4648 Base32 test vectors (encode direction):")
    for td, b32 in zip(test_data, base32_string):
        got = base32_encode(td)
        print(f"t={td} expected='{b32}' got='{got}'", "OK" if got == b32 else "FAIL")

    print("\nRFC 4648 Base32 test vectors (decode direction):")
    for b32, td in zip(base32_string, test_data):
        got = base32_decode(b32)
        print(f"t={td} expected='{td}' got='{got}'",
            "OK" if got == td.encode('utf-8') else "FAIL")


    # ------------------------------------------------------
    # 5. Round-Trip Base32 Encode/Decode Tests
    # ------------------------------------------------------
    print("\nRound-Trip Base32 encode/decode tests:")
    test_data = [
        b"hello",  # Simple string
        b"1234567890",  # Numeric string
        b"\x00\x01\x02\x03\x04\x05",  # Binary data
        b"ABCDEF1234567890",  # Alphanumeric string
        b"abcdefghijklmnopqrstuvwxyz",  # Lowercase letters
    ]
    for i, data in enumerate(test_data):
        try:
            # Encode and then decode the data
            encoded = base32_encode(data)
            decoded = base32_decode(encoded)
            print(f"Test {i} - Round-trip: OK (input: {data}, encoded: "
                f"{encoded}, decoded: {decoded}) ")
            # Check that the round-trip decode matches the original data
            assert decoded == data, (f"Decoded data doesn't match original "
                f"(input: {data}, decoded: {decoded})")
        except Exception as e:
            print(f"Test {i} - Round-trip: FAIL ({e})")
            raise e
