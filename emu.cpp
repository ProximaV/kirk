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
    case KIRK_INSN_0D_MOV32A:
    case KIRK_INSN_0E_MOV32AA:
    case KIRK_INSN_11_CMPI:
    case KIRK_INSN_12_CMPPLUS:
    case KIRK_INSN_13_CMPA:
    case KIRK_INSN_16_SUBA:
    case KIRK_INSN_19_ADDI:
    case KIRK_INSN_1B_ADDA:
    case KIRK_INSN_21_ADDC:
    case KIRK_INSN_29_SUBI:
    case KIRK_INSN_39_ANDI:
    case KIRK_INSN_3A_ANDA:
    case KIRK_INSN_43_MOV16:
    case KIRK_INSN_44_ORA:
    case KIRK_INSN_49_XORI:
    case KIRK_INSN_4B_XORA:
    case KIRK_INSN_53_MOV128:
    case KIRK_INSN_80_INC32:
    case KIRK_INSN_88_DEC32:
    case KIRK_INSN_90_LSH:
    case KIRK_INSN_98_NAND:
    case KIRK_INSN_A0_SETMODE:
    case KIRK_INSN_B0_BYTESWAP:
    case KIRK_INSN_C0_TEST:
    case KIRK_INSN_C8_BITSET:
    case KIRK_INSN_D0_BITCLEAR:
    case KIRK_INSN_DA_CLRZ:
    case KIRK_INSN_DB_SETZ:
    case KIRK_INSN_F0_RET:
    case KIRK_INSN_F8_INTR:
        len = KIRK_emu_standard_insn(insn); break;
    case KIRK_INSN_E0_B:
    case KIRK_INSN_E1_BNZ:
    case KIRK_INSN_E2_BZ:
    case KIRK_INSN_E3_BGT:
    case KIRK_INSN_E4_BLT:
    case KIRK_INSN_E8_CALL:
    case KIRK_INSN_E9_CALL2:
        len = KIRK_emu_call_branch(insn); break;
    default: len = 0; break;
    }

    if (len && !has_insn_feature(insn.itype, CF_STOP))
        insn_add_cref(insn, insn.ea + len, 0, fl_F);


    return 1;
}