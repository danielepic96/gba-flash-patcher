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
- **Improved erase/program timing**: added toggle-bit (DQ6) polling for
  both sector erase and byte programming, matching the completion-detection
  method used by official Nintendo flash drivers, for more reliable timing
  on real Macronix hardware.

Tested and confirmed working on a ChisCart v1.1 (1Mbit Macronix MX29L010)

## EEPROM support fixes (from v1.1)

This fork also fixes EEPROM save support, which previously often required
a two-step workaround (converting to SRAM with GBATA first, then patching
with this tool). The patcher simply couldn't recognize the real EEPROM
read/write/identify functions in several games — different compilers
produce slightly different machine code for the same operation, and the
original signatures only matched one specific form.

Added a clean way to handle multiple known variants of the same function
side by side, plus several new variants found by analyzing real games —
most of the missing cases were on the write side. Also fixed how the
EEPROM metadata pointer gets located, so it resolves correctly regardless
of which variant matched.

Tested and confirmed fully working (read, write, verify, identify all
found and patched) on several different EEPROM games. If you hit a game
where the write function still isn't found, it's most likely just another
untested compiled variant — happened four times already, so more are
likely out there.
