# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: Copyright 2025 Sam Blenny
#
# See NOTES.md for documentation links and pinout info.
#
import atexit
import board
import busio
import collections
import digitalio
import displayio
from fourwire import FourWire
from micropython import const
from pwmio import PWMOut
import terminalio
import time

from adafruit_24lc32 import EEPROM_I2C
from adafruit_apds9960.apds9960 import APDS9960
from adafruit_display_text import label
from adafruit_ds3231 import DS3231
from adafruit_st7789 import ST7789

from eeprom_db import check_eeprom_format, is_slot_in_use, load_totp_account
from sb_totp import base32_encode, totp_sha1


PROX_THRESHOLD = const(4)


# Begin TFT backlight dimming (100% brightness is PWM duty_cycle=0xffff)
BACKLIGHT_ON = const(26214)  # 40% of 0xffff
BACKLIGHT_OFF = const(0)
backlight = PWMOut(board.TFT_BACKLIGHT, frequency=500, duty_cycle=BACKLIGHT_ON)

# Configure CLUE's 240x240 ST7789 TFT display with a 4x scaled text label
displayio.release_displays()
spi = busio.SPI(board.TFT_SCK, MOSI=board.TFT_MOSI)
# print("spi frequency", spi.frequency) # default is 32MHz which works fine
display_bus = FourWire(spi, command=board.TFT_DC, chip_select=board.TFT_CS,
    reset=board.TFT_RESET)
display = ST7789(display_bus, width=240, height=240, rowstart=80, bgr=True,
    rotation=0, auto_refresh=False)
group = displayio.Group()
display.root_group = group
display.refresh()
textbox = label.Label(font=terminalio.FONT, scale=4, color=0xefef00)
textbox.anchor_point = (0, 0)
textbox.anchored_position = (0, 0)
textbox.line_spacing = 1.0  # default is 1.25
group.append(textbox)

# Set an atexit handler to release the display once code.py ends. This is an
# aesthetic filter to prevent CircuitPython's supervisor from hijacking the
# display to show its own stuff, which I don't want to see.
def atexit_shutdown_display():
    try:
        textbox.text = 'OFFLINE'
        display.refresh()
        displayio.release_displays()
        spi.deinit()
    except AttributeError:
        pass
atexit.register(atexit_shutdown_display)

# Prepare for talking to the I2C RTC, EEPROM, and proximity sensor chips
i2c = busio.I2C(board.SCL, board.SDA, frequency=250_000)
eeprom = EEPROM_I2C(i2c)
rtc = DS3231(i2c)
apds = APDS9960(i2c)
apds.enable_proximity = True

def format_datetime(t):
    date = '%04d-%02d-%02d' % (t[0:3])
    time = '%02d:%02d:%02d' % (t[3:6])
    return (date, time)

# Print startup info to check on EEPROM and RTC
print('EEPROM[:32]:', eeprom[:32])
print('DS3231 datetime: %s %s' % format_datetime(rtc.datetime))


# Load TOTP account slot data from EEPROM database (label + base32 secret)
TOTPAccount = collections.namedtuple("TOTPAccount",
    ["slot", "label", "secret_b32"])
accounts = []
try:
    check_eeprom_format(eeprom)
    for slot in [i for i in range(1, 16) if is_slot_in_use(eeprom, i)]:
        label, secret_bytes = load_totp_account(eeprom, slot)
        secret_b32 = base32_encode(secret_bytes)
        accounts.append(TOTPAccount(slot, label, secret_b32))
except ValueError as e:
    print(e)

# Track index of the selected account, or None if no accounts are available
selected_account_index = None if len(accounts) == 0 else 0

def select_next_account():
    # Increment selected account index, modulo total number of accounts
    global selected_account_index
    if len(accounts) == 0:
        return
    selected_account_index = (selected_account_index + 1) % len(accounts)

def select_prev_account():
    # Decrement selected account index, modulo total number of accounts
    global selected_account_index
    if len(accounts) == 0:
        return
    selected_account_index = ((selected_account_index + len(accounts) - 1) %
        len(accounts))

def get_selected_totp(unix_time):
    # Get TOTP slot, label, and code for the selected account
    if selected_account_index is None:
        return ('', '', '')
    acct = accounts[selected_account_index]
    code = totp_sha1(acct.secret_b32, unix_time, digits=6, period=30)
    return (acct.slot, acct.label, code)

# Print summary from loading the EEPROM account database
print(f"Loaded data for {len(accounts)} TOTP account slots from EEPROM")
for i, a in enumerate(accounts):
    selected = i == selected_account_index
    print(f" slot {a.slot}: '{a.label}'")
if selected_account_index is not None:
    print("Selected Slot:", accounts[selected_account_index].slot)


# Prepare for using CLUE buttons to cycle through TOTP account slots
button_A = digitalio.DigitalInOut(board.BUTTON_A)
button_B = digitalio.DigitalInOut(board.BUTTON_B)
button_A.pull = digitalio.Pull.UP
button_B.pull = digitalio.Pull.UP
prev_a = button_A.value
prev_b = button_B.value


# ---
# Main Loop
# ---
t = rtc.datetime
prev_t = t
prev_prox = apds.proximity > PROX_THRESHOLD  # True means hand near sensor
bl_enable = True
need_refresh = True
slot, label, totp_code = get_selected_totp(time.mktime(t))
while True:

    # Update display only when backlight is on
    if bl_enable:
        (date, time_str) = format_datetime(t)
        textbox.text = '%s\n%s\n%s %s\n%s' % (date, time_str, slot, label,
            totp_code)
        display.refresh()
        need_refresh = False

    # Wait until second rolls over
    while t.tm_sec == prev_t.tm_sec and not need_refresh:

        # 1. Spend about 100ms fast-polling for input events
        t_10Hz = time.monotonic() + 0.1
        while time.monotonic() < t_10Hz and not need_refresh:

            # Check Button A
            va = button_A.value
            if (not va) and prev_a:
                # Falling edge of button A press -> select next TOTP account
                select_next_account()
                need_refresh = True
            prev_a = va

            # Check Button B
            vb = button_B.value
            if (not vb) and prev_b:
                # Falling edge of button B press -> select previous account
                select_prev_account()
                need_refresh = True
            prev_b = vb

            # Check Proximity Sensor
            prox_event = apds.proximity > PROX_THRESHOLD
            if prox_event != prev_prox:
                prev_prox = prox_event
                if prox_event:
                    # Toggle backlight on leading edge of proximity event
                    bl_enable = not bl_enable
                    dc = BACKLIGHT_ON if bl_enable else BACKLIGHT_OFF
                    backlight.duty_cycle = dc
                    if not bl_enable:
                        textbox.text = ''
                        display.refresh()

            # Sleep to rate limit I2C, debounce buttons, do VM background tasks
            time.sleep(0.05)

        # 2. Poll RTC at about 10 Hz to detect when seconds have changed
        if bl_enable:
            t = rtc.datetime

    # After the seconds have changed, update the previous time
    prev_t = t

    # RTC seconds have incremented (or need refresh), so check the TOTP period
    if t.tm_sec % 30 == 0 or need_refresh:
        # Generate new totp code at multiples of 30 seconds
        unix_time = time.mktime(rtc.datetime)
        slot, label, totp_code = get_selected_totp(unix_time)
