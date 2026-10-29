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
    static const char* get_intr_unit_name(uint32 mask);
};
CASSERT(sizeof(out_kirk_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(out_kirk_t);

const char* out_kirk_t::get_intr_unit_name(uint32 mask)
{
    switch (mask)
    {
    case KIRK_INTR_DMA:  return "DMA";
    case KIRK_INTR_HOST: return "HOST";
    case KIRK_INTR_ECC:  return "ECC";
    case KIRK_INTR_SHA1: return "SHA1";
    case KIRK_INTR_AES:  return "AES";
    case KIRK_INTR_PRNG: return "PRNG";
    case KIRK_INTR_TRNG: return "TRNG";
    case KIRK_INTR_MATH: return "MATH";
    default:             return nullptr;
    }
}

void out_kirk_t::out_print_address(const op_t& x, ea_t pc, int n)
{
    const char* prefix = nullptr;

    refinfo_t ri;
    if (get_refinfo(&ri, pc, n))
    {
        switch (ri.type())
        {
        case REF_LOW8:   prefix = "low8";   break;
        case REF_LOW16:  prefix = "low16";  break;
        case REF_HIGH8:  prefix = "high8";  break;
        case REF_HIGH16: prefix = "high16"; break;
        default:         prefix = nullptr;  break;
        }
    }

    if (prefix != nullptr)
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
    if (prefix != nullptr)
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
    case KIRK_OPERAND_MEM_DIRECT:
        if (x.n == 1 && x.offb == 4)
        {
            // Immediate operand converted via manual offset (refinfo_t)
            out_print_address(x, pc, x.n);
        }
        else
        {
            out_symbol('(');
            out_print_address(x, pc, x.n);
            out_symbol(')');
        }
        break;

    case KIRK_OPERAND_MEM_INDIRECT:
        out_symbol('[');
        out_symbol('(');
        out_print_address(x, pc, x.n);
        out_symbol(')');
        out_symbol(']');
        break;

    case KIRK_OPERAND_UIMM:
        out_value(x, OOFW_32 | OOFS_NOSIGN | OOF_NUMBER | OOFW_IMM);
        break;

    case KIRK_OPERAND_BIT_INDEX:
    {
        out_value(x, OOFW_32 | OOFS_NOSIGN | OOF_NUMBER | OOFW_IMM);
        if (insn.Op1.type == o_mem)
        {
            kirk_t& pm = *static_cast<kirk_t*>(procmod);
            const char* bit_name = pm.find_ioport_bit_name(insn.Op1.addr, static_cast<size_t>(x.value));
            if (bit_name != nullptr)
            {
                out_char(' ');
                out_symbol('(');
                out_line(bit_name, COLOR_IMPNAME);
                out_symbol(')');
            }
        }
        break;
    }

    case KIRK_OPERAND_INTR_MASK:
    {
        out_value(x, OOFW_32 | OOFS_NOSIGN | OOF_NUMBER | OOFW_IMM);
        const char* unit = get_intr_unit_name(static_cast<uint32>(x.value));
        if (unit != nullptr)
        {
            out_char(' ');
            out_symbol('(');
            out_line(unit, COLOR_IMPNAME);
            out_symbol(')');
        }
        break;
    }

    case KIRK_OPERAND_BRANCH:
        if (!out_name_expr(x, x.addr))
            out_value(x, OOF_ADDR | OOFS_NOSIGN | OOFW_IMM);
        break;

    default:
        return false;
    }

    return true;
}

void out_kirk_t::out_insn(void)
{
    out_mnem();

    if (insn.Op1.type != o_void)
    {
        out_one_operand(0);
        if (insn.Op2.type != o_void)
        {
            out_symbol(',');
            out_char(' ');
            out_one_operand(1);
        }
    }

    flush_outbuf();
}
