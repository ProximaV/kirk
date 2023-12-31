/* IDP emulator for KIRK - (c) Proxima 2023
*/


#include "kirk.hpp"




// ********** x-invalid: --invalid--

static int KIRK_emu_x_invalid(const insn_t& insn)
{
    return 0;
}

static int KIRK_emu_standard_insn(const insn_t& insn)
{
    if (insn.Op1.type == o_mem)
    {
        insn.add_dref(insn.Op1.addr, insn.ea, dr_O);
    }
    if (insn.Op2.type == o_mem)
    {
        insn.add_dref(insn.Op2.addr, insn.ea, dr_O);
    }

    return insn.size;
}




static int KIRK_emu_call_branch(const insn_t& insn)
{
    unsigned int val;
    if (insn.Op1.type == o_near)
    {
        val = insn.Op1.addr;
    }
    else {
        val = insn.Op1.value;
    }

    cref_t flag = has_insn_feature(insn.itype, CF_CALL) ? fl_CN : fl_JN;
    insn_add_cref(insn, val, 0, flag);

    return 4;
}





// Emulator entry
int kirk_t::kirk_emu(const insn_t& insn)
{
    int len;
    switch (insn.itype)
    {
    case KIRK_INSN_X_INVALID:
        len = KIRK_emu_x_invalid(insn); break;
    case KIRK_INSN_09_STORE:
    case KIRK_INSN_0B_MOV32:
    case KIRK_INSN_0D:
    case KIRK_INSN_0E:
    case KIRK_INSN_11_CMP:
    case KIRK_INSN_12:
    case KIRK_INSN_13:
    case KIRK_INSN_16:
    case KIRK_INSN_19:
    case KIRK_INSN_1B:
    case KIRK_INSN_21:
    case KIRK_INSN_29:
    case KIRK_INSN_39:
    case KIRK_INSN_3A_AND:
    case KIRK_INSN_43:
    case KIRK_INSN_44:
    case KIRK_INSN_49:
    case KIRK_INSN_4B:
    case KIRK_INSN_53_MOV128:
    case KIRK_INSN_80:
    case KIRK_INSN_88:
    case KIRK_INSN_90:
    case KIRK_INSN_98:
    case KIRK_INSN_A0:
    case KIRK_INSN_B0:
    case KIRK_INSN_C0_TEST:
    case KIRK_INSN_C8:
    case KIRK_INSN_D0:
    case KIRK_INSN_DA:
    case KIRK_INSN_DB:
    case KIRK_INSN_F0_RET:
    case KIRK_INSN_F8:
        len = KIRK_emu_standard_insn(insn); break;
    case KIRK_INSN_E0_BRA:
    case KIRK_INSN_E1_BNE:
    case KIRK_INSN_E2_BEQ:
    case KIRK_INSN_E3_BGE:
    case KIRK_INSN_E4_BLE:
    case KIRK_INSN_E8_CALL:
    case KIRK_INSN_E9_CALL2:
        len = KIRK_emu_call_branch(insn); break;
    default: len = 0; break;
    }

    if (len && !has_insn_feature(insn.itype, CF_STOP))
        insn_add_cref(insn, insn.ea + len, 0, fl_F);


    return 1;
}