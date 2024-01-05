/* KIRK IDP output - (c) Proxima 2023
*/

#include "kirk.hpp"
class out_kirk_t : public outctx_t
{
    out_kirk_t(void) = delete; // not used
public:
    bool out_operand(const op_t& x);
    void out_insn(void);
private:
    void out_print_address(const op_t& x, ea_t pc, int n = 0);
};
CASSERT(sizeof(out_kirk_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(out_kirk_t);


void out_kirk_t::out_print_address(const op_t& x, ea_t pc, int n)
{
    const char* prefix;

    refinfo_t ri;
    if (get_refinfo(&ri, pc, n))
    {
        switch (ri.type())
        {
        case REF_LOW8: prefix = "low8"; break;
        case REF_LOW16: prefix = "low16"; break;
        case REF_HIGH8: prefix = "high8"; break;
        case REF_HIGH16: prefix = "high16"; break;
        default: prefix = NULL; break;
        }
    }
    else
    {
        prefix = NULL;
    }

    if (prefix)
    {
        out_line(prefix, COLOR_MACRO);
        out_line("(", COLOR_MACRO);
    }
    if (!out_name_expr(x, x.addr))
    {
        out_tagon(COLOR_ERROR);
        out_value(x, OOF_ADDR | OOFW_32 | OOF_NUMBER | OOFS_NOSIGN);
        out_tagoff(COLOR_ERROR);
        remember_problem(PR_NONAME, insn.ea);
    }
    if (prefix)
    {
        out_line(")", COLOR_MACRO);
    }
}

bool out_kirk_t::out_operand(const op_t& x)
{
    uint16 opindex = x.kirk_type;
    ea_t pc = insn.ea;

    switch (opindex)
    {
    case KIRK_OPERAND_MEM:
        out_print_address(x, pc, x.n);
        break;
    case KIRK_OPERAND_UIMM:
        out_value(x, OOFW_32 | OOFS_NOSIGN | OOF_NUMBER | OOFW_IMM);
        break;
    case KIRK_OPERAND_BRANCH:
        if (!out_name_expr(x, x.addr)) out_value(x, OOF_ADDR | OOFS_NOSIGN | OOFW_IMM);
        break;
    default:
        return 0;
    }

    return 1;
}
void out_kirk_t::out_insn(void)
{
    switch (insn.itype)
    {
        ///($addr)
    case KIRK_INSN_B0_BYTESWAP:
    case KIRK_INSN_80_INC32:
    case KIRK_INSN_88_DEC32:
        out_mnem();
        out_symbol('(');
        out_one_operand(0);
        out_symbol(')');
        break;
        //($addr1), $data
        //($addr1), $imm
    case KIRK_INSN_09_STORE:
    case KIRK_INSN_11_CMP:
    case KIRK_INSN_12:
    case KIRK_INSN_19_ADDI:
    case KIRK_INSN_21:
    case KIRK_INSN_29_SUB:
    case KIRK_INSN_39_ANDI:
    case KIRK_INSN_3A_ORI:
    case KIRK_INSN_49:
    case KIRK_INSN_90_LSH:
    case KIRK_INSN_98_NAND:
    case KIRK_INSN_A0_SETMODE:
    case KIRK_INSN_C0_TEST:
    case KIRK_INSN_C8_BITSET:
    case KIRK_INSN_D0_BITCLEAR:
        out_mnem();
        out_symbol('(');
        out_one_operand(0);
        out_symbol(')');
        out_symbol(',');
        out_char(' ');
        out_one_operand(1);
        break;
        // ($addr1), ($addr1)
    case KIRK_INSN_0B_MOV32:
    case KIRK_INSN_0D:
    case KIRK_INSN_0E:
    case KIRK_INSN_13:
    case KIRK_INSN_16_XOR32:
    case KIRK_INSN_1B_ADDA:
    case KIRK_INSN_43_MOV16:
    case KIRK_INSN_44:
    case KIRK_INSN_4B:
    case KIRK_INSN_53_MOV128:
        out_mnem();
        out_symbol('(');
        out_one_operand(0);
        out_symbol(')');
        out_symbol(',');
        out_char(' ');
        out_symbol('(');
        out_one_operand(1);
        out_symbol(')');
        break;
        
        //$imm, $imm
    case KIRK_INSN_F8_INTR:
        out_mnem();
        out_one_operand(0);
        out_symbol(',');
        out_char(' ');
        out_one_operand(1);
        break;
        //$branch
    case KIRK_INSN_E0_B:
    case KIRK_INSN_E1_BNZ:
    case KIRK_INSN_E2_BZ:
    case KIRK_INSN_E3_BGT:
    case KIRK_INSN_E4_BLT:
    case KIRK_INSN_E8_CALL:
    case KIRK_INSN_E9_CALL2:
        out_mnem();
        out_one_operand(0);
        break;
        // ret
    case KIRK_INSN_DA_CLRZ:
    case KIRK_INSN_DB_SETZ:
    case KIRK_INSN_F0_RET:
        out_mnem();
        break;
    default:
        break;
    }
    flush_outbuf();
}
