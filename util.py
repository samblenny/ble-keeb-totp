# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Copyright 2024 Sam Blenny
#
# This is meant to be imported from the CircuitPython REPL to set the DS3231
# clock after installing a new battery.
#
# Usage example:
# >>> import util
# DS3231 datetime: 2000-01-01 02:06:52
# >>> util.set_clock()
# Set DS3231 RTC time...
#    year: 2025
#   month: 11
#     day: 25
#    hour: 00
#  minute: 01
# seconds: 02
# new RTC time:  2025-11-25 00:01:02
# >>>
#
import board
import busio
import time
from time import mktime, sleep, struct_time

from adafruit_24lc32 import EEPROM_I2C
from adafruit_datetime import datetime
from adafruit_ds3231 import DS3231

from sb_totp import base32_decode, parse_uri


i2c = busio.I2C(board.SCL, board.SDA, frequency=250_000)
rtc = DS3231(i2c)
eeprom = EEPROM_I2C(i2c)


def set_clock():
    print("Set DS3231 RTC time...")
    try:
        y    = int(input("   year: "))
        mon  = int(input("  month: "))
        d    = int(input("    day: "))
        h    = int(input("   hour: "))
        min_ = int(input(" minute: "))
        s    = int(input("seconds: "))
        t = struct_time((y, mon, d, h, min_, s, 0, -1, -1))
        rtc.datetime = t
        print("new RTC time: ", now())
    except ValueError as e:
        print("ERROR Bad value:", e)

def now():
    # Return RTC time formatted as a string
    return "%04d-%02d-%02d %02d:%02d:%02d" % ((rtc.datetime)[0:6])


def format_eeprom():
    # 1. Confirm if user really wants to format the EEPROM
    yn = input("Are you sure? This will erase all data. (y/n): ")
    if yn.strip().lower() != 'y':
        print("Operation canceled.")
        return

    # 2. Check EEPROM length
    if (len_ := len(eeprom)) != 4096:
        raise ValueError("Expected EEPROM length 4096 bytes, got:", len_)

    # 3. Write header with 'TOTP' magic bytes and reserved fields
    print("Writing header page...")
    eeprom[0:32] = b'TOTP' + (b'\x00' * 28) # magic + nulls for reserved bytes

    # 4. Zero all record slots (each record is 64 bytes or 2 pages)
    blank_page = b'\x00' * 32
    print("Zeroing 127 pages:")
    for i in range(1, 128):  # 127 pages, 32 bytes each, skip page 0 (header)
        print(".", end=('\n' if i % 64 == 0 else ''))
        start = i * 32
        eeprom[start:start+32] = blank_page

    print("\nEEPROM formatted successfully.")


def add_totp_account():
    # 1. Check for 'TOTP' magic bytes in the EEPROM
    if eeprom[0:4] != b'TOTP':
        raise ValueError("EEPROM not formatted. Run format_eeprom() first.")

    # 2. Prompt for slot number
    slot = int(input("Enter slot number (1-15): "))
    if not (1 <= slot <= 15):
        raise ValueError("Invalid slot number. Must be between 1 and 15.")

    # 3. Check if the slot is already in use
    in_use_marker = 4 + (slot - 1)
    if eeprom[in_use_marker] == b'\xFF':  # Slot is in use
        if input("Slot is in use. Overwrite? (y/n): ").strip().lower() != 'y':
            print("Operation canceled")
            return

    # 4. Prompt for label (max 8 chars)
    label_bytes = input("Enter label (max 8 chars): ").strip().encode('utf-8')
    if len(label_bytes) > 8:
        raise ValueError("Label too long. Max 8 utf-8 bytes.")
    label_padded = label_bytes + b'\x00' * (8 - len(label_bytes))  # null pad

    # 5. Prompt for TOTP URI
    uri = input("Enter TOTP URI: ").strip()

    # 6. Parse URI, extract secret and decode
    secret_b32 = parse_uri(uri)
    secret_bytes = base32_decode(secret_b32)  # Decode the Base32 secret

    # Check if the secret is too long
    if len(secret_bytes) > 32:
        raise ValueError("Too many secret bytes. Must be 32 bytes or fewer.")

    # Pad the secret to 32 bytes if shorter (with 0x00 padding). This is okay
    # to do now because the HMAC hash will pad short keys later anyway.
    secret_bytes += b'\x00' * (32 - len(secret_bytes))

    # 7. Write label and secret to the EEPROM slot
    base = 32 + (slot - 1) * 64
    eeprom[base+0:base+8] = label_padded     # 8 null padded label bytes
    eeprom[base+8:base+32] = b'\x00' * 24    # 24 reserved bytes
    eeprom[base+32:base+64] = secret_bytes   # 32 null padded secret bytes

    # 8. Mark slot in use in the header
    eeprom[in_use_marker] = 0xFF

    print(f"Record added to slot {slot}.")


def erase_totp_account():
    # 1. Check for 'TOTP' magic bytes in the EEPROM
    if eeprom[0:4] != b'TOTP':
        raise ValueError("EEPROM not formatted. Run format_eeprom() first.")

    # 2. Prompt for slot number
    slot = int(input("Enter slot number (1-15) to erase: "))
    if not (1 <= slot <= 15):
        raise ValueError("Invalid slot number. Must be between 1 and 15.")

    # 3. Erase the slot: set all its bytes to 0x00
    base = 32 + (slot - 1) * 64
    eeprom[base:base + 64] = b'\x00' * 64  # Clear the slot's record (64 bytes)

    # 4. Mark the slot as free in the header
    in_use_marker = 4 + (slot - 1)
    eeprom[in_use_marker] = 0x00  # Mark slot as not in use

    print(f"Slot {slot} has been erased.")


def list_totp_accounts():
    # Check for 'TOTP' magic bytes in the EEPROM
    if eeprom[0:4] != b'TOTP':
        raise ValueError("EEPROM not formatted. Run format_eeprom() first.")

    # Iterate through each of the 15 possible slots
    for slot in range(1, 16):
        in_use_marker = 4 + (slot - 1)
        base = 32 + ((slot - 1) * 64)

        # Check if the slot is in use by looking at the in-use marker
        if eeprom[in_use_marker] == b'\xFF':
            # Slot is in use, extract the label, removing null padding
            label = eeprom[base:base+8].decode('utf-8').rstrip('\x00')
            print(f"Slot {slot}: '{label}'")
        else:
            print(f"Slot {slot}: -- empty --")
