# KIRK Processor Module for IDA Pro

An IDA Pro processor module (`PLFM_KIRK`, processor short name `KIRK`) for disassembling and analyzing the internal mask-ROM firmware of the PSP **KIRK** cryptographic coprocessor (`Star Trek PSP Processors: KIRK big endian`).

Compatible with IDA Pro 8.x and 9.x (`__EA64__`).

---

## Architecture Overview

KIRK is controlled by a custom big-endian, registerless, memory-to-memory 32-bit/128-bit micro-sequencer with a Harvard address space:

* **`CODE` (`0x0000..0x3FFF`)**: Big-endian internal mask ROM. Instructions are 32-bit aligned and either **4 bytes** (single word) or **8 bytes** (instruction word followed by a 32-bit immediate). Branch and call targets encode 12-bit word addresses (`word_idx << 2`). Subroutine `call`/`ret` uses an internal hardware return-address stack.
* **`DATA` (`0xE0000000..0xE000FFFF`)**: Unified memory-mapped I/O (MMIO) and scratchpad SRAM. Instruction address fields (`addr1` in bits `[23:12]`, `addr2` in bits `[11:0]`) encode 12-bit 32-bit-word offsets mapped to `0xE0000000 | (word_idx << 2)`. Firmware convention uses `0xE0003F00..0xE0003F3C` as 16 workspace word registers (`R0..R15`).
* **Condition Flags**: Unsigned condition flags (`Z`, `C`) updated by arithmetic, bitwise, compare, and `btest`/`clrz`/`setz` instructions. For `btest (src), bit`, `Z` latches `(MEM[src] >> bit) & 1`.

---

## Features

* **Table-Driven Instruction Analysis (`ana.cpp`)**:
  * Decodes all 42 hardware-valid opcodes (37 ROM-attested silicon instructions plus 5 orthogonal Group-A addressing modes), with optical-decap bit-error ghost opcodes removed.
  * Enforces 5-bit immediate validation (`(insn & 0xFE0) == 0`) on barrel-shift (`lsh`, `rsh`) and bit-manipulation (`btest`, `bitset`, `bitclear`) instructions to prevent false decoding of data words.
  * Recovers the known 1-bit decap shift on the reset vector at `0x0000` (`_reset` → `_start`).
* **Direct, Indirect & Offset Operand Rendering (`out.cpp`)**:
  * Direct word-addressed RAM/MMIO access: `(SYMBOL)` (`MEM[addr]`).
  * Indirect RAM pointer dereference: `[(SYMBOL)]` (`MEM[MEM[addr]]`).
  * Supports manual offset conversion (`refinfo_t`) on 32-bit immediate operands, resolving word-index pointers (`0xE0000000 | (imm32 << 2)`) into symbolic data references.
* **Symbolic Hardware Accelerator & Bitfield Annotations (`out.cpp`, `reg.cpp`, `cfg/kirk.cfg`)**:
  * Annotates `wfe` (`0xF8`) 24-bit accelerator event masks (`DMA`, `HOST`, `ECC`, `SHA1`, `AES`, `PRNG`, `TRNG`, `MATH`), e.g. `wfe 0x100000 (TRNG)`.
  * Annotates `btest`, `bitset`, and `bitclear` operands with named MMIO register bitfields from `cfg/kirk.cfg`, e.g. `btest (ECC_RESULT), 0 (ECC_VALID)` and `bitclear (AES_CMD), 1 (AES_INIT_IV)`.
  * Automatically loads `kirk.cfg` port/bit metadata in memory (`IORESP_NONE`) when opening pre-existing `.i64` databases without overwriting user-defined symbols.
* **Cross-Reference & Control-Flow Emulation (`emu.cpp`)**:
  * Creates typed data items (`dt_dword` and 16-byte `dt_byte16` for `mov128`) and read/write/offset data cross-references (`dr_R`, `dr_W`, `dr_O`), including pointer-read xrefs on indirect `[(addr)]` operands.
  * Tracks calls (`fl_CN`), conditional/unconditional jumps (`fl_JN`), sequential fallthrough (`fl_F`), and basic-block terminators (`b`, `ret`).

---

## Instruction Set

### Group A — ALU & Data Movement (`opcode[7:3]` = operation, `opcode[2:0]` = addressing mode)

Group A instructions share a 3-bit addressing mode in `opcode[2:0]`:

| Mode | Length | Syntax | Semantics |
| :---: | :---: | :--- | :--- |
| `1` | 8 B | `(addr1), imm32` | Direct destination, 32-bit immediate source |
| `2` | 8 B | `[(addr1)], imm32` | Indirect destination `MEM[MEM[addr1]]`, 32-bit immediate source |
| `3` | 4 B | `(addr2), (addr1)` | Direct destination, direct source |
| `4` | 4 B | `[(addr2)], (addr1)` | Indirect destination, direct source |
| `5` | 4 B | `(addr2), [(addr1)]` | Direct destination, indirect source |
| `6` | 4 B | `[(addr2)], [(addr1)]` | Indirect destination, indirect source |

| Opcode(s) | Mnemonics | Width | Description |
| :--- | :--- | :---: | :--- |
| `0x09..0x0E` | `store`, `storea`, `mov32`, `mov32ia`, `mov32a`, `mov32aa` | 32-bit | 32-bit immediate store and memory-to-memory move |
| `0x11..0x13`, `0x16` | `cmpi`, `cmpia`, `cmpa`, `cmpaa` | 32-bit | Unsigned 32-bit compare (`dst - src`, updates `Z` and `C`) |
| `0x19`, `0x1B` | `addi`, `adda` | 32-bit | 32-bit unsigned addition (`dst += src`, updates `Z` and `C`) |
| `0x21` | `addc` | 32-bit | 32-bit unsigned add with carry (`dst += imm32 + C`) |
| `0x29` | `subi` | 32-bit | 32-bit unsigned subtraction (`dst -= imm32`, updates `Z` and `C`) |
| `0x39`, `0x3A` | `andi`, `andia` | 32-bit | Bitwise AND (`dst &= imm32`, updates `Z`) |
| `0x41`, `0x43`, `0x44` | `ori`, `or`, `ora` | 32-bit | Bitwise OR (`dst \|= src`, updates `Z`) |
| `0x49`, `0x4B`, `0x4E` | `xori`, `xora`, `xoraa` | 32-bit | Bitwise XOR (`dst ^= src`, updates `Z`) |
| `0x53` | `mov128` | 128-bit | 16-byte (4-word) aligned block transfer `(addr2) <= (addr1)` |

### Group B & C — Unary, Shift, Bit, Control & Synchronization (`0x80..0xF8`)

| Opcode | Mnemonic | Length | Operands | Description |
| :---: | :--- | :---: | :--- | :--- |
| `0x80` | `inc32` | 4 B | `(dst)` | Increment 32-bit word (`MEM[dst] += 1`) |
| `0x88` | `dec32` | 4 B | `(dst)` | Decrement 32-bit word (`MEM[dst] -= 1`) |
| `0x90` | `lsh` | 4 B | `(dst), shift5` | 32-bit logical shift left by `0..31` |
| `0x98` | `rsh` | 4 B | `(dst), shift5` | 32-bit logical shift right by `0..31` |
| `0xA0` | `setmode` | 4 B | `(ctrl), imm12` | Write 12-bit command/strobe to hardware accelerator control port |
| `0xB0` | `byteswap` | 4 B | `(dst)` | In-place 32-bit endian byte swap (`bswap32`) |
| `0xC0` | `btest` | 4 B | `(src), bit5` | Test bit `0..31` (`Z <= (MEM[src] >> bit5) & 1`) |
| `0xC8` | `bitset` | 4 B | `(dst), bit5` | Set bit `0..31` (`MEM[dst] \|= (1u << bit5)`) |
| `0xD0` | `bitclear` | 4 B | `(dst), bit5` | Clear bit `0..31` (`MEM[dst] &= ~(1u << bit5)`) |
| `0xDA` | `clrz` | 4 B | — | Clear zero flag (`Z <= 0`) |
| `0xDB` | `setz` | 4 B | — | Set zero flag (`Z <= 1`) |
| `0xE0` | `b` | 4 B | `target` | Unconditional branch to `target` |
| `0xE1` | `bnz` | 4 B | `target` | Branch if `Z == 0` (not equal / tested bit clear) |
| `0xE2` | `bz` | 4 B | `target` | Branch if `Z == 1` (equal / tested bit set) |
| `0xE3` | `bhi` | 4 B | `target` | Branch if unsigned higher (`>`) |
| `0xE4` | `blo` | 4 B | `target` | Branch if unsigned lower (`<`) |
| `0xE8` | `call` | 4 B | `target` | Push `PC + 4` onto hardware return stack and jump to `target` |
| `0xF0` | `ret` | 4 B | — | Pop return address from hardware stack into `PC` |
| `0xF8` | `wfe` | 4 B | `mask24` | Wait-for-event pipeline barrier on 24-bit accelerator IRQ mask |

---

## Hardware MMIO Map (`cfg/kirk.cfg`)

| Base Address | Unit | `wfe` Mask | Description |
| :--- | :--- | :--- | :--- |
| `0xE0000000` | `ECC` | `0x000100` | 160-bit prime-field ECDSA sign/verify & scalar point multiplication (`ECC_P`, `ECC_A`, `ECC_B`, `ECC_N`, `ECC_R2_MOD_P`, `ECC_R2_MOD_N`, `ECC_Gx/Gy`, `ECC_OUT_X/Y`) |
| `0xE0000CC0` | `SHA1` | `0x004000` | Hardware SHA-1 engine (`SHA1_IN_SIZE`, 32-bit `SHA1_IN_DATA` FIFO, 160-bit `SHA1_RESULT`) |
| `0xE0000E00` | `AES` | `0x010000` | AES-128 ECB / CBC / CMAC engine (`AES_CMD` bits: `AES_DECRYPT`, `AES_INIT_IV`, `AES_CBC`, `AES_CMAC`) |
| `0xE0001080` | `PRNG` | `0x080000` | FIPS 186-2 Appendix 3.1 `G(t, c)` SHA-1 PRNG (`PRNG_XKEY`, `PRNG_XSEED`, `PRNG_RESULT`) |
| `0xE0001100` | `TRNG` | `0x100000` | Hardware 256-bit true random entropy source (`TRNG_MODE`, `TRNG_OUT0`, `TRNG_OUT1`) |
| `0xE0001180` | `MATH` | `0x400000` | BigNum `512-bit mod 256-bit` modular reduction unit (`MATH_IN_HI/LO`, `MATH_MOD_HI/LO`, `MATH_OUT_HI/RESULT`) |
| `0xE0001240` | Key Vault | — | Per-console fuse keys (`PCK_KEY0..3`), AES key vault selector (`hw_keyslot`), and ECDSA curve ROM (`hw_curve_param_id`) |
| `0xE0003800` | `DMA` | `0x000001` | Internal 32-byte staging DMA engine (`hw_dma_ctrl`, `hw_dma_addr`, `hw_dma_size`, `DMA_BUF`) |
| `0xE0003880` | `HOST` | `0x000002` | Host PSP command/phase/status interface (`PSP_KIRK_CMD`, `PSP_KIRK_SRC`, `PSP_KIRK_DST`, `PSP_KIRK_RESULT`) |
| `0xE0003EC0` | SRAM | — | Boot/FIPS status (`isRetailMode`, `FIPS_STATUS`), workspace registers (`R0..R15`), and firmware state (`kirk_semaphor`) |

---

## Repository Structure

| Path | Purpose |
| :--- | :--- |
| `kirk.hpp` | Processor state (`kirk_t`), operand subtypes (`KIRK_OPERAND_TYPE`), and `wfe` unit bitmasks |
| `ins.hpp` / `ins.cpp` | Instruction IDs (`KIRK_INSN_TYPE`) and `Instructions[]` feature table |
| `ana.cpp` | Table-driven instruction decoder (`OpcodeTable` and `kirk_t::kirk_ana`) |
| `emu.cpp` | Control-flow and data cross-reference emulator (`kirk_t::kirk_emu`) |
| `out.cpp` | Disassembly formatter with MMIO bitfield and `wfe` unit annotations (`out_kirk_t`) |
| `reg.cpp` | IDA `procmod_t` lifecycle, `kirkasm` definition, `iohandler_t` integration, and `LPH` export |
| `cfg/kirk.cfg` | Memory map (`ROM`/`RAM`), entry points, MMIO register symbols, and hardware bit definitions |
| `vs/kirk.sln` | Standalone Visual Studio solution (`Release\|x64` → `kirk.dll`, `Release64\|x64` → `kirk64.dll`) |
| `CMakeLists.txt` | CMake build definition for `ida-cmake` / IDA SDK 9.x |
| `makefile` | Legacy IDA SDK `module.mak` build file |

---

## Building

Place or clone this directory at `<ida-sdk>/src/module/kirk`.

### Option 1: Visual Studio / MSBuild (Windows)

Open `vs\kirk.sln` in Visual Studio 2022 (or newer), or build from PowerShell / Developer Command Prompt:

```powershell
msbuild vs\kirk.vcxproj /t:Rebuild /p:Configuration=Release /p:Platform=x64
msbuild vs\kirk.vcxproj /t:Rebuild /p:Configuration=Release64 /p:Platform=x64
```

A post-build step automatically deploys `kirk.dll` / `kirk64.dll` to `%APPDATA%\Hex-Rays\IDA Pro\procs` and `cfg\kirk.cfg` to `%APPDATA%\Hex-Rays\IDA Pro\cfg\kirk.cfg`.

### Option 2: CMake (`ida-cmake`)

When building via the IDA SDK CMake setup (`IDASDK`), `CMakeLists.txt` registers the `kirk` processor target via `ida_add_procmod` and automatically copies the compiled module and `cfg/kirk.cfg` to `%APPDATA%\Hex-Rays\IDA Pro` when `APPDATA` is defined.

### Option 3: IDA SDK `makefile`

1. Configure your IDA SDK environment (`IDASDK`).
2. Add `kirk` to `DIRS` in `<ida-sdk>/src/module/makefile`.
3. Run `make` from `<ida-sdk>/src/module/kirk` and copy `cfg/kirk.cfg` into your IDA `cfg` directory.

---

## Usage in IDA Pro

1. Open a raw KIRK mask-ROM binary (such as `kirk-original-rom.bin`) in IDA Pro.
2. Select processor type **`Star Trek PSP Processors: KIRK big endian` (`KIRK`)** and click **Set**.
3. Keep the ROM load address at `0x0000` and accept the **`KIRK`** I/O device configuration dialog when prompted — IDA will automatically create the `ROM` (`0x0000..0x3FFF`) and `RAM` (`0xE0000000..0xE000FFFF`) segments, define `_reset` (`0x0000`) and `_start` (`0x0004`), and populate all hardware MMIO register and bitfield symbols.

---

## License

This project is licensed under the MIT License.
