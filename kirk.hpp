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



#define OPVAL_H_GR_BASE  0
#define OPVAL_H_CSR_BASE  32
#define REGS_COUNT 65
#define OPVAL_HW_H_SP 28

typedef enum kirk_operand_type {
    KIRK_OPERAND_PC,
    KIRK_OPERAND_MEM,
    KIRK_OPERAND_IMM,
    KIRK_OPERAND_UIMM,
    KIRK_OPERAND_BRANCH,
} KIRK_OPERAND_TYPE;

/* Number of operands types.  */
#define MAX_OPERANDS 7

/* Maximum number of operands referenced by any insn.  */
#define MAX_OPERAND_INSTANCES 3

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
    bool kirk_is_switch(switch_info_t* si, const insn_t& insn);
    void load_from_idb();
    bool kirk_find_ioport_bit(outctx_t& ctx, int port, int bit);
};

#define PROCMOD_NODE_NAME "$ KIRK"
#define PROCMOD_NAME KIRK

extern int data_id;

#endif
