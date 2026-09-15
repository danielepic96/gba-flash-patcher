# GBA Flash Patcher

Patches an EEPROM or SRAM GBA game to save on Flash 512K and 1Mbit

## Additional fixes (fork)

- **Fixed a stack overflow crash**: the sector buffer (up to 2KB) was
  allocated as a stack-local array inside the hijacked SRAM function, using
  the host game's own call stack. This could easily overflow and corrupt
  memory, causing a crash on the very first save. The buffer now lives at a
  fixed EWRAM address instead.
- **Fixed silent read failures**: some games reuse the same generic copy
  routine for both reading and writing SRAM, swapping which pointer is the
  SRAM address depending on direction. The patcher previously only
  recognized the write direction, silently breaking all reads. It now
  detects direction based on which pointer falls in the SRAM/Flash address
  range.
- **Fixed a verify-function misidentification bug**: some games have a
  byte-compare "verify" function that shares the exact same prologue as the
  write function (WAITCNT setup) but differs later in the loop body
  (compare vs copy). The patcher was misidentifying and hooking this as if
  it were a write function, breaking save verification and causing the game
  to loop indefinitely retrying the save. The patcher now distinguishes the
  two variants by checking loop-body bytes and routes verify calls
  correctly.
- **Improved erase/program timing**: from v2.0 restored Data-Polling (DQ7)
  instead of Toggle-Bit (DQ6) and added program/erase timeout based on DQ5
  on AMD/JEDEC chips (like Macronix). Greatly optimized program/erase
  routines on all chips (faster savings).
- **Added support for Intel/Sharp and other chip manufacturers**: from v2.0
  has been added support for other Flash manufacturers. If the manufacturer
  ID is not recognized, the payload will fallback on AMD/JEDEC protocol.
- **Added several new signatures**: since v1.5, the patcher covers most (if
  not all) EEPROM and SRAM signatures, if you find a game which doesn't hook
  all save functions, feel free to open an Issue ticket.

