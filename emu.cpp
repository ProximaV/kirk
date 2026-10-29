/* IDP emulator for KIRK - (c) Proxima 2023
*/

#include "kirk.hpp"

static void handle_mem_operand(const insn_t& insn, const op_t& x, bool is_read, bool is_write)
{
    if (x.type != o_mem)
        return;

    insn.create_op_data(x.addr, x);

    if (x.kirk_type == KIRK_OPERAND_MEM_INDIRECT)
    {
        // An indirect operand [(addr)] reads the pointer stored at x.addr
        insn.add_dref(x.addr, x.offb, dr_R);
        return;
    }

    // If this operand was converted from an immediate via manual refinfo_t (offb == 4),
    // record an offset reference (dr_O).
    if (x.n == 1 && x.offb == 4)
    {
        insn.add_dref(x.addr, x.offb, dr_O);
        return;
    }

    if (is_read)
        insn.add_dref(x.addr, x.offb, dr_R);
    if (is_write)
        insn.add_dref(x.addr, x.offb, dr_W);
}

static int KIRK_emu_standard_insn(const insn_t& insn)
{
    uint32 feature = insn.get_canon_feature(PH);

    if (insn.Op1.type == o_mem)
    {
        bool use1 = (feature & CF_USE1) != 0;
        bool chg1 = (feature & CF_CHG1) != 0;
        handle_mem_operand(insn, insn.Op1, use1, chg1);
    }

    if (insn.Op2.type == o_mem)
    {
        bool use2 = (feature & CF_USE2) != 0;
        handle_mem_operand(insn, insn.Op2, use2, false);
    }

    return insn.size;
}

static int KIRK_emu_call_branch(const insn_t& insn)
{
    ea_t target = (insn.Op1.type == o_near) ? insn.Op1.addr : static_cast<ea_t>(insn.Op1.value);
    cref_t flag = has_insn_feature(insn.itype, CF_CALL) ? fl_CN : fl_JN;
    insn.add_cref(target, insn.Op1.offb, flag);
    return insn.size;
}

// Emulator entry
int kirk_t::kirk_emu(const insn_t& insn)
{
    if (insn.itype == KIRK_INSN_X_INVALID || insn.size == 0)
        return 0;

    int len = 0;
    switch (insn.itype)
    {
    case KIRK_INSN_E0_B:
    case KIRK_INSN_E1_BNZ:
    case KIRK_INSN_E2_BZ:
    case KIRK_INSN_E3_BHI:
    case KIRK_INSN_E4_BLO:
    case KIRK_INSN_E8_CALL:
        len = KIRK_emu_call_branch(insn);
        break;

    default:
        len = KIRK_emu_standard_insn(insn);
        break;
    }

    if (len > 0 && !has_insn_feature(insn.itype, CF_STOP))
        insn.add_cref(insn.ea + len, 0, fl_F);

    return 1;
}
