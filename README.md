<!-- SPDX-License-Identifier: MIT -->
<!-- SPDX-FileCopyrightText: Copyright 2025 Sam Blenny -->
# BLE Keeb TOTP

TOTP token with BLE HID keyboard output, Adafruit CLUE, precision RTC, 4-key
NeoKey mechanical keypad, and a 4KB EEPROM for TOTP seed storage.


## Hardware

The code here is written for:

- [Adafruit CLUE - nRF52840 Express](https://www.adafruit.com/product/4500)
- [Adafruit DS3231 Precision RTC](https://www.adafruit.com/product/5188)
- [Adafruit 24LC32 I2C EEPROM](https://www.adafruit.com/product/5146)
- [Adafruit NeoKey 1x4 QT I2C Mechanical Key Switches with NeoPixels](https://www.adafruit.com/product/4980)

Additional Parts:
- [Kailh Mechanical Key Switches Cherry MX Brown Compatible](https://www.adafruit.com/product/4954)
- [Purple DSA Keycaps for MX Compatible Switches](https://www.adafruit.com/product/5003)


## Install & Setup

You will need to:

1. Ensure your CLUE board has an [up to date bootloader](https://learn.adafruit.com/adafruit-clue/update-bootloader)

2. Download CircuitPython 10.0.3 .UF2 file from the circuitpython.org downloads
   page for
   [CLUE NRF52840 Express](https://circuitpython.org/board/clue_nrf52840_express/)

3. Follow Adafruit's
   [CircuitPython on CLUE](https://learn.adafruit.com/adafruit-clue/circuitpython)
   Learn guide to install CircuitPython: plug CLUE into a computer, double-click
   CLUE's reset button, wait for CLUEBOOT drive, drag UF2 file onto CLUEBOOT
   drive, wait for copy to finish.

4. Unplug the CLUE and assemble the rest of the hardware

5. Get the project bundle from the release page and copy its code and library
   files from the 10.x directory to your board's `CIRCUITPY` drive


## Set RTC Time in UTC

When you first install a battery in the DS3231, the time will be wildly wrong.
You can set the time from the REPL by importing the `util` module then calling
`util.set_clock()`, like this:

```
Adafruit CircuitPython 10.0.3 on 2025-10-17; Adafruit CLUE nRF52840 Express with nRF52840
>>> import util
>>> util.now()
'2000-01-01 02:06:52'
>>> util.set_clock()
Set DS3231 RTC time...
   year: 2025
  month: 11
    day: 25
   hour: 00
 minute: 01
seconds: 02
new RTC time:  2025-11-25 00:01:02
>>> # wait a while, then check the time
>>> util.now()
'2025-11-25 00:06:02'
>>>
```

When you set the time, use a GPS or NTP synchronized reference that shows UTC
time with seconds (e.g. https://samblenny.github.io/totp-util/clock/ ). Don't
set the clock according to your local timezone. You must use UTC.

Each of the "year:", "month:", "day:", etc. prompts come from python's
`input()` function. The text on the left is the input prompt shown by
`set_clock()`, and the numbers on the right are an example of what you might
type for your response. When you hit return or enter for the seconds line, the
time will be set immediately.


## Store TOTP Accounts in EEPROM Database

The `util` module has several functions for managing the 4KB EEPROM as a
database of TOTP account details. You can enter QR code URIs with a 2D barcode
reader or by decoding elsewhere then copying and pasting. The EEPROM database
only stores a short (8 character) label and the 32 byte decoded seed (from the
`&secret=...` TOTP URI query parameter). The only supported options for
`&algorithm=`, `&digits=`, and `&period=` are SHA1, 6 digits, and 30 seconds.
That will work for many services that use TOTP. If you need something else, you
can modify the code.

To get started managing the EEPROM database, open the USB serial console and do
the Ctrl-C thing to get into the CircuitPython REPL. From there, import util
then call `util.menu()` to see what's available. The first time, you will need
to format the EEPROM. After that, you can add, erase, or copy accounts as you
like. There are 15 available slots (chosen to fit what can be selected with
chording key-presses on a 4 key NeoKey keypad).

This is an example of how it might look to use the menu:

```
>>> import util
>>> util.menu()
Available functions:

 1. add_totp_account()    - Add a new TOTP account.
 2. copy_totp_account()   - Copy a TOTP account to another slot.
 3. erase_totp_account()  - Erase a TOTP account from EEPROM.
 4. format_eeprom()       - Format the EEPROM for TOTP storage.
 5. get_time()            - Get the current DS3231 RTC time.
 6. list_totp_accounts()  - List all stored TOTP accounts.
 7. set_time()            - Set the DS3231 RTC time.

Choose a function by number (or Enter to cancel): 6
Slot 1: 'adafruit'
Slot 2: 'gmail'
Slot 3: 'discord'
Slot 4: -- empty --
Slot 5: -- empty --
Slot 6: -- empty --
Slot 7: -- empty --
Slot 8: -- empty --
Slot 9: -- empty --
Slot 10: -- empty --
Slot 11: -- empty --
Slot 12: -- empty --
Slot 13: -- empty --
Slot 14: -- empty --
Slot 15: -- empty --
>>>
```
