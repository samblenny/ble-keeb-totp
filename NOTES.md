# Notes


Related Learn Guides:
- https://learn.adafruit.com/circuitpython-display-text-library/types-of-labels
- https://learn.adafruit.com/adafruit-ds3231-precision-rtc-breakout
- https://learn.adafruit.com/adafruit-24lc32-i2c-eeprom-breakout-32kbit-4-kb
- https://learn.adafruit.com/neokey-1x4-qt-i2c (I2C 4 key keyboard)
- https://learn.adafruit.com/adafruit-apds9960-breakout (CLUE light sensor)
- https://learn.adafruit.com/adafruit-1-3-and-1-54-240-x-240-wide-angle-tft-lcd-displays
  (CLUE 1.3" 240x240 ST7789 display)
- https://learn.adafruit.com/ble-hid-keyboard-buttons-with-circuitpython/overview


Related API Docs:
- https://docs.circuitpython.org/en/latest/shared-bindings/atexit/
- https://docs.circuitpython.org/en/latest/shared-bindings/supervisor/
- https://docs.circuitpython.org/en/latest/shared-bindings/busio/#busio.SPI
- https://docs.circuitpython.org/projects/ds3231/en/stable/api.html
- https://docs.circuitpython.org/en/latest/shared-bindings/pwmio/
- https://docs.circuitpython.org/projects/apds9960/en/latest/api.html
- https://docs.circuitpython.org/projects/ble/en/latest/
- https://docs.circuitpython.org/projects/hid/en/latest/


RFCs:
- [RFC 4226: HOTP](https://datatracker.ietf.org/doc/html/rfc4226)
- [RFC 6238: TOTP](https://datatracker.ietf.org/doc/html/rfc6238)

Other Specs:
- https://www.bluetooth.com/specifications/assigned-numbers/ (BLE appearance)


Pins provided by `import board`:
```
A0              A1              A2              A3
A4              A5              A6              A7
ACCELEROMETER_GYRO_INTERRUPT    BUTTON_A        BUTTON_B
D0              D1              D10             D11
D12             D13             D14             D15
D16             D17             D18             D19
D2              D20             D3              D4
D5              D6              D7              D8
D9              DISPLAY         I2C             L
LED             MICROPHONE_CLOCK                MICROPHONE_DATA
MISO            MOSI            NEOPIXEL        P0
P1              P10             P11             P12
P13             P14             P15             P16
P17             P18             P19             P2
P20             P3              P4              P5
P6              P7              P8              P9
PROXIMITY_LIGHT_INTERRUPT       RX              SCK
SCL             SDA             SPEAKER         SPI
STEMMA_I2C      TFT_BACKLIGHT   TFT_CS          TFT_DC
TFT_MOSI        TFT_RESET       TFT_SCK         TX
UART            WHITE_LEDS
```
