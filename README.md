# GBA Flash Patcher

Patches a GBA game that saves to **SRAM** or **EEPROM** so that it saves to a
**Flash** chip instead. It is meant for reproduction cartridges and flashcarts
that have a Flash save chip and no battery-backed SRAM.

## What it does

The patcher looks for the game's save routines by signature, replaces them
with jumps to a small payload, and writes the payload into free space in the
ROM (expanding the ROM if there is none). The payload then turns each SRAM or
EEPROM access into the right Flash commands.

Only the 64 KB of the first Flash bank are used, so the same patched ROM works
on 512 Kbit and 1 Mbit save chips.

Games that already save to Flash are refused: they do not need this tool.

## What the fork adds

### Fixes
- **Crash on first save.** The sector buffer was on the game's stack and
  overflowed it. It now lives at a fixed address at the top of EWRAM.
- **Reads that silently failed.** Some games use one generic copy routine for
  both reading and writing the save. The payload now tells the direction from
  which pointer is in the save area.
- **Verify routines taken for write routines.** They are now told apart, and
  the value they return matches what the original routines return.
- **Wait states.** The payload sets the save-area wait state itself, as the
  routines it replaces did. Slow chips no longer miss commands.
- **Unreliable erase and program.** Completion is detected properly, with
  time limits, so a chip that does not answer cannot hang the game.
- **Missing EEPROM metadata.** A game whose EEPROM size is not known yet no
  longer makes the payload read garbage.
- **Address checks** that the replaced routines performed are back, so a
  wrong signature match cannot overwrite a valid block.

### More games
- More signature variants for SRAM and EEPROM routines.
- EEPROM games with **fixed 6-bit addressing** (for example Rayman Advance),
  which have no routine that reports the EEPROM size.
- Clear messages when a ROM cannot be patched, with the reason.

### Fewer erases
- A sector is erased only when a bit has to go back from 0 to 1. Otherwise
  only the bytes that changed are programmed.
- After an erase, bytes that must stay `0xFF` are read back, not programmed.
- **EEPROM journal.** EEPROM games write 8 bytes at a time, which used to
  cost about one sector erase per block. Writes now go to a journal in blank
  space and the Flash is erased only when the journal is full. Two copies of
  the base data mean that a power cut during compaction leaves the previous
  state readable. Saves in the previous format are converted on first use.

### Save chip detection
The chip is identified once and each operation uses its own parameters,
following the behaviour of the official GBA Flash save libraries:

| Chip | ID | Notes |
|---|---|---|
| SST 39VF512 | `BF D4` | erase is checked and repeated if needed |
| SST 39LF/VF010, 020, 040 | `BF D5`–`D7` | found on repro carts |
| Macronix MX29L512, MX29L010 | `C2 1C`, `C2 09` | |
| Panasonic MN63F805MNP | `32 1B` | |
| Sanyo LE26FV10N1TS | `62 13` | |
| Atmel AT29LV512 | `1F 3D` | 128-byte page writes, no journal |
| anything else | | cautious path |

Flash reads run from RAM, as the official libraries do.

### Save converter
A single HTML page that converts saves between what the patched game stores
on the Flash chip and the normal `.sav` format used by emulators (EEPROM
journal to plain EEPROM, and Flash to and from SRAM).

## Usage

```
patcher game.gba
```
On Windows you can drag the ROM onto `patcher.exe`. The result is written
next to the original as `game_flash512.gba`. The original file is not changed.

## Building

You need devkitARM for the payload and a normal C compiler for the patcher.

```
gcc -O2 bin2c.c -o bin2c

arm-none-eabi-gcc -mcpu=arm7tdmi -nostartfiles -nodefaultlibs -mthumb -Os \
    -fno-toplevel-reorder payload.c -T payload.ld -o payload.elf
arm-none-eabi-objcopy -O binary payload.elf payload.bin

./bin2c payload.bin payload_bin.c payload_bin
gcc -O2 patcher.c payload_bin.c -o patcher
```

`-fno-toplevel-reorder` is required: the payload depends on the order of its
functions.

## Limits

- **Cartridges with SRAM or FRAM do not need this.** The payload sends Flash
  commands, which on SRAM or FRAM would be written into the save as data.
- **The save chip must use JEDEC commands and 4 KB sectors** (or be the Atmel
  listed above). Intel/Sharp-style chips are not supported.
- **The payload uses the top 2064 bytes of EWRAM** (`0x0203F7F0`–`0x0203FFFF`).
  A game that uses that memory itself will not work.
- **A patched EEPROM save is not a plain EEPROM dump.** Use the save converter
  to move it to an emulator or back.
- **The ROM header is left unchanged**, so tools still see the original save
  type.

## Testing

Tested on repro cartridge with SST 39VF040 save chip on both SRAM and EEPROM 
patched games.

The Macronix, Panasonic, Sanyo, SST 39VF512 and Atmel entries follow the
official libraries and the chips' datasheets but have **not** been tried on
those chips. Reports are welcome.

## Credits and license

Original project by [metroid-maniac](https://github.com/metroid-maniac).
Fork by [danielepic96](https://github.com/danielepic96).

Released under the MIT license, like the original. See `LICENSE`.
