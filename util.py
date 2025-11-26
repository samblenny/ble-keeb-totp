# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Copyright 2024 Sam Blenny
#
# This is meant to be imported from the CircuitPython REPL to set the DS3231
# clock after installing a new battery.
#
# See NOTES.md for documentation links.
#
# Usage example (CircuitPython REPL in USB serial console):
#
#     >>> import util
#     >>> util.menu()
#     Available functions:
#
#      1. add_totp_account()    - Add a new TOTP account.
#      2. copy_totp_account()   - Copy a TOTP account to another slot.
#      3. erase_totp_account()  - Erase a TOTP account from EEPROM.
#      4. format_eeprom()       - Format the EEPROM for TOTP storage.
#      5. get_time()            - Get the current DS3231 RTC time.
#      6. list_totp_accounts()  - List all stored TOTP accounts.
#      7. set_time()            - Set the DS3231 RTC time.
#
#     Choose a function by number (or Enter to cancel):
#     Operation canceled.
#     >>>
#
import board
import busio
import time
from time import mktime, sleep, struct_time

from adafruit_24lc32 import EEPROM_I2C
from adafruit_datetime import datetime
from adafruit_ds3231 import DS3231

from eeprom_db import check_eeprom_format, is_slot_in_use, load_totp_account
from sb_totp import base32_decode, parse_uri


i2c = busio.I2C(board.SCL, board.SDA, frequency=250_000)
rtc = DS3231(i2c)
eeprom = EEPROM_I2C(i2c)


def set_time():
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


def get_time():
    print(now())


def get_slot_input():
    # Prompts the user for a valid slot number
    slot = int(input("Enter slot number (1-15): "))
    if not (1 <= slot <= 15):
        raise ValueError("Invalid slot number. Must be between 1 and 15.")
    return slot


def confirm_overwrite(slot):
    # Prompts the user to confirm overwriting a slot if it is in use
    if is_slot_in_use(eeprom, slot):  # Slot is in use
        overwrite = input("Slot is in use. Overwrite? (y/n): ").strip().lower()
        if overwrite != 'y':
            print("Operation canceled.")
            return False
    return True


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


def write_slot_data(slot, label_padded, secret_bytes):
    # Writes label and secret data to the specified slot
    base = 32 + (slot - 1) * 64
    eeprom[base+0:base+8] = label_padded      # 8 null padded label bytes
    eeprom[base+8:base+32] = b'\x00' * 24     # 24 reserved bytes
    eeprom[base+32:base+64] = secret_bytes    # 32 null padded secret bytes


def add_totp_account():
    # 1. Check for 'TOTP' magic bytes in the EEPROM
    check_eeprom_format(eeprom)

    # 2. Prompt for slot number
    slot = get_slot_input()

    # 3. Check if the slot is already in use
    if is_slot_in_use(eeprom, slot):
        if not confirm_overwrite(slot):
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
    write_slot_data(slot, label_padded, secret_bytes)

    # 8. Mark slot in use in the header
    in_use_marker = 4 + (slot - 1)
    eeprom[in_use_marker] = 0xFF

    print(f"Record added to slot {slot}.")


def erase_totp_account():
    # 1. Check for 'TOTP' magic bytes in the EEPROM
    check_eeprom_format(eeprom)

    # 2. Prompt for slot number
    slot = get_slot_input()

    # 3. Erase the slot: set all its bytes to 0x00
    base = 32 + (slot - 1) * 64
    eeprom[base:base + 64] = b'\x00' * 64  # Clear the slot's record (64 bytes)

    # 4. Mark the slot as free in the header
    in_use_marker = 4 + (slot - 1)
    eeprom[in_use_marker] = 0x00  # Mark slot as not in use

    print(f"Slot {slot} has been erased.")


def list_totp_accounts():
    # Check for 'TOTP' magic bytes in the EEPROM
    check_eeprom_format(eeprom)

    # Iterate through each of the 15 possible slots
    for slot in range(1, 16):
        try:
            # Load label and secret from EEPROM for the given slot
            label, _ = load_totp_account(eeprom, slot)
            print(f"Slot {slot}: '{label}'")
        except ValueError:
            # If the slot isn't in use, we get a ValueError
            print(f"Slot {slot}: -- empty --")


def copy_totp_account():
    # Prompt for the source slot number
    src_slot = get_slot_input()

    # Check if the source slot is in use
    if not is_slot_in_use(eeprom, src_slot):
        raise ValueError(f"Source slot {src_slot} is not in use.")

    # Prompt for the destination slot number
    dest_slot = get_slot_input()

    # Check if the destination slot is in use
    if is_slot_in_use(eeprom, dest_slot):
        # Prompt to confirm overwriting the destination slot
        if not confirm_overwrite(dest_slot):
            return

    # Define the base addresses for the source and destination slots
    src_base = 32 + (src_slot - 1) * 64
    dest_base = 32 + (dest_slot - 1) * 64

    # Copy TOTP account data (label + secret) from the source to destination
    eeprom[dest_base:dest_base + 64] = eeprom[src_base:src_base + 64]

    # Update the in-use marker for the destination slot
    eeprom[4 + (dest_slot - 1)] = 0xFF

    print(f"TOTP account copied from slot {src_slot} to slot {dest_slot}.")


def menu():
    # List the available functions with brief descriptions
    print("Available functions:")
    print()
    print(" 1. add_totp_account()    - Add a new TOTP account.")
    print(" 2. copy_totp_account()   - Copy a TOTP account to another slot.")
    print(" 3. erase_totp_account()  - Erase a TOTP account from EEPROM.")
    print(" 4. format_eeprom()       - Format the EEPROM for TOTP storage.")
    print(" 5. get_time()            - Get the current DS3231 RTC time.")
    print(" 6. list_totp_accounts()  - List all stored TOTP accounts.")
    print(" 7. set_time()            - Set the DS3231 RTC time.")
    print()

    # Prompt for which function to invoke
    choice = input(
        "Choose a function by number (or Enter to cancel): ").strip()

    # If the user entered an empty string, do nothing
    if choice == "":
        print("Operation canceled.")
        return

    # Convert input to an integer and invoke the corresponding function
    choice = int(choice)
    if choice == 1:
        add_totp_account()
    elif choice == 2:
        copy_totp_account()
    elif choice == 3:
        erase_totp_account()
    elif choice == 4:
        format_eeprom()
    elif choice == 5:
        get_time()
    elif choice == 6:
        list_totp_accounts()
    elif choice == 7:
        set_time()
    else:
        raise ValueError(f"Invalid choice: {choice}")
