/* KIRK IDP hardware defines - (c) Proxima 2023
*/

#ifndef __KIRK_HPP
#define __KIRK_HPP
#pragma warning (disable : 4146)
#include <ida.hpp>
#include <idp.hpp>
#include <ua.hpp>
#include <name.hpp>
#include <auto.hpp>
#include <bytes.hpp>
#include <diskio.hpp>
#include <problems.hpp>
#include <frame.hpp>
#include <jumptable.hpp>
#include <lines.hpp>
#include <loader.hpp>
#include <offset.hpp>
#include <segment.hpp>
#include <segregs.hpp>
#include <kernwin.hpp>
#include "ins.hpp"
#include "../idaidp.hpp"
#include "../iohandler.hpp"

#define kirk_type specval_shorts.low

constexpr ea_t KIRK_RAM_BASE = 0xE0000000;

typedef enum kirk_operand_type : uint16
{
    KIRK_OPERAND_NONE = 0,
    KIRK_OPERAND_MEM_DIRECT,    // (addr)   -> Direct RAM/MMIO word access: MEM[addr]
    KIRK_OPERAND_MEM_INDIRECT,  // [(addr)] -> Indirect RAM pointer access: MEM[MEM[addr]]
    KIRK_OPERAND_UIMM,          // Unsigned immediate (32-bit data, 12-bit imm, 5-bit shift)
    KIRK_OPERAND_BIT_INDEX,     // 5-bit bit index (0..31) with optional MMIO bit annotation
    KIRK_OPERAND_INTR_MASK,     // 24-bit hardware accelerator interrupt/event mask
    KIRK_OPERAND_BRANCH,        // 12-bit code word branch/call target (word_idx << 2)
} KIRK_OPERAND_TYPE;

// Legacy alias for compatibility
#define KIRK_OPERAND_MEM KIRK_OPERAND_MEM_DIRECT

// Hardware accelerator interrupt/event mask bits for 0xF8 (wfe)
enum kirk_intr_mask_t : uint32
{
    KIRK_INTR_DMA  = 0x000001, // 0xE0003800: Internal DMA Engine
    KIRK_INTR_HOST = 0x000002, // 0xE0003880: PSP Host Interface
    KIRK_INTR_ECC  = 0x000100, // 0xE0000000: ECC Engine
    KIRK_INTR_SHA1 = 0x004000, // 0xE0000CC0: SHA-1 Engine
    KIRK_INTR_AES  = 0x010000, // 0xE0000E00: AES Engine
    KIRK_INTR_PRNG = 0x080000, // 0xE0001080: PRNG Engine
    KIRK_INTR_TRNG = 0x100000, // 0xE0001100: Hardware TRNG Engine
    KIRK_INTR_MATH = 0x400000, // 0xE0001180: BigNum Math Engine

    KIRK_INTR_DEV4 = KIRK_INTR_TRNG, // Legacy alias
};

/* IDP exports */

DECLARE_PROC_LISTENER(idb_listener_t, struct kirk_t);

struct kirk_t : public procmod_t
{
    netnode helper;
    iohandler_t ioh = iohandler_t(helper);
    idb_listener_t idb_listener = idb_listener_t(*this);

    virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;

    int kirk_ana(insn_t* _insn);
    int kirk_emu(const insn_t& insn);
    void load_from_idb();
    const char* find_ioport_bit_name(ea_t port, size_t bit) const;
    bool kirk_find_ioport_bit(outctx_t& ctx, ea_t port, size_t bit);
};

#define PROCMOD_NODE_NAME "$ KIRK"
#define PROCMOD_NAME KIRK

extern int data_id;

#endif
