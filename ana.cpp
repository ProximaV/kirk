/* KIRK IDP analysis - (c) Proxima 2023
*/
#pragma warning (disable : 4146)
#include "kirk.hpp"

typedef uint32 INSN;

static inline int f_opcode(INSN insn)   { return (insn >> 24) & 0xFF; }
static inline ea_t f_addr1(INSN insn)   { return (((insn >> 12) & 0xFFF) << 2) | KIRK_RAM_BASE; }
static inline ea_t f_addr2(INSN insn)   { return ((insn & 0xFFF) << 2) | KIRK_RAM_BASE; }
static inline int f_imm1(INSN insn)     { return (insn >> 12) & 0xFFF; }
static inline int f_imm2(INSN insn)     { return insn & 0xFFF; }
static inline uint32 f_mask24(INSN insn){ return insn & 0xFFFFFF; }
static inline ea_t f_branch(INSN insn)  { return (insn & 0xFFF) << 2; }

enum kirk_format_t : uint8
{
    FMT_INVALID = 0,
    FMT_NOOPS,        // 4B: no operands
    FMT_ADDR,         // 4B: (addr1)
    FMT_ADDR_SHIFT5,  // 4B: (addr1), shift5 (bits [11:5] must be 0)
    FMT_ADDR_BIT5,    // 4B: (addr1), bit5   (bits [11:5] must be 0)
    FMT_ADDR_IMM12,   // 4B: (addr1), imm12
    FMT_ADDR_DATA,    // 8B: (addr1), imm32
    FMT_IND_DATA,     // 8B: [(addr1)], imm32
    FMT_ADDR_ADDR,    // 4B: (addr2), (addr1)
    FMT_IND_ADDR,     // 4B: [(addr2)], (addr1)
    FMT_ADDR_IND,     // 4B: (addr2), [(addr1)]
    FMT_IND_IND,      // 4B: [(addr2)], [(addr1)]
    FMT_BRANCH,       // 4B: branch_target
    FMT_INTR,         // 4B: mask24
};

struct kirk_opcode_desc_t
{
    uint8 opcode;
    KIRK_INSN_TYPE itype;
    kirk_format_t format;
    op_dtype_t dtype;
};

static const kirk_opcode_desc_t OpcodeTable[] =
{
    // 0x09..0x0E: 32-bit Move family (top = 0x01, mode = 1..6)
    { 0x09, KIRK_INSN_09_STORE,    FMT_ADDR_DATA,   dt_dword  },
    { 0x0A, KIRK_INSN_0A_STOREA,   FMT_IND_DATA,    dt_dword  },
    { 0x0B, KIRK_INSN_0B_MOV32,    FMT_ADDR_ADDR,   dt_dword  },
    { 0x0C, KIRK_INSN_0C_MOV32IA,  FMT_IND_ADDR,    dt_dword  },
    { 0x0D, KIRK_INSN_0D_MOV32A,   FMT_ADDR_IND,    dt_dword  },
    { 0x0E, KIRK_INSN_0E_MOV32AA,  FMT_IND_IND,     dt_dword  },

    // 0x11..0x16: 32-bit Compare family (top = 0x02, mode = 1..3, 6)
    { 0x11, KIRK_INSN_11_CMPI,     FMT_ADDR_DATA,   dt_dword  },
    { 0x12, KIRK_INSN_12_CMPIA,    FMT_IND_DATA,    dt_dword  },
    { 0x13, KIRK_INSN_13_CMPA,     FMT_ADDR_ADDR,   dt_dword  },
    { 0x16, KIRK_INSN_16_CMPAA,    FMT_IND_IND,     dt_dword  },

    // 0x19..0x1B: 32-bit Add family (top = 0x03, mode = 1, 3)
    { 0x19, KIRK_INSN_19_ADDI,     FMT_ADDR_DATA,   dt_dword  },
    { 0x1B, KIRK_INSN_1B_ADDA,     FMT_ADDR_ADDR,   dt_dword  },

    // 0x21: 32-bit Add with Carry (top = 0x04, mode = 1)
    { 0x21, KIRK_INSN_21_ADDC,     FMT_ADDR_DATA,   dt_dword  },

    // 0x29: 32-bit Subtract (top = 0x05, mode = 1)
    { 0x29, KIRK_INSN_29_SUBI,     FMT_ADDR_DATA,   dt_dword  },

    // 0x39..0x3A: 32-bit Bitwise AND family (top = 0x07, mode = 1, 2)
    { 0x39, KIRK_INSN_39_ANDI,     FMT_ADDR_DATA,   dt_dword  },
    { 0x3A, KIRK_INSN_3A_ANDIA,    FMT_IND_DATA,    dt_dword  },

    // 0x41..0x44: 32-bit Bitwise OR family (top = 0x08, mode = 1, 3, 4)
    { 0x41, KIRK_INSN_41_ORI,      FMT_ADDR_DATA,   dt_dword  },
    { 0x43, KIRK_INSN_43_OR,       FMT_ADDR_ADDR,   dt_dword  },
    { 0x44, KIRK_INSN_44_ORA,      FMT_IND_ADDR,    dt_dword  },

    // 0x49..0x4E: 32-bit Bitwise XOR family (top = 0x09, mode = 1, 3, 6)
    { 0x49, KIRK_INSN_49_XORI,     FMT_ADDR_DATA,   dt_dword  },
    { 0x4B, KIRK_INSN_4B_XORA,     FMT_ADDR_ADDR,   dt_dword  },
    { 0x4E, KIRK_INSN_4E_XORAA,    FMT_IND_IND,     dt_dword  },

    // 0x53: 128-bit (16-byte) Block Move (top = 0x0A, mode = 3)
    { 0x53, KIRK_INSN_53_MOV128,   FMT_ADDR_ADDR,   dt_byte16 },

    // 0x80, 0x88: 32-bit Increment / Decrement (top = 0x10, 0x11)
    { 0x80, KIRK_INSN_80_INC32,    FMT_ADDR,        dt_dword  },
    { 0x88, KIRK_INSN_88_DEC32,    FMT_ADDR,        dt_dword  },

    // 0x90, 0x98: Logical Shifts (top = 0x12, 0x13)
    { 0x90, KIRK_INSN_90_LSH,      FMT_ADDR_SHIFT5, dt_dword  },
    { 0x98, KIRK_INSN_98_RSH,      FMT_ADDR_SHIFT5, dt_dword  },

    // 0xA0: Hardware Unit Mode / Strobe (top = 0x14)
    { 0xA0, KIRK_INSN_A0_SETMODE,  FMT_ADDR_IMM12,  dt_dword  },

    // 0xB0: 32-bit Endian Byte Swap (top = 0x16)
    { 0xB0, KIRK_INSN_B0_BYTESWAP, FMT_ADDR,        dt_dword  },

    // 0xC0, 0xC8, 0xD0: Bit Test / Set / Clear (top = 0x18..0x1A)
    { 0xC0, KIRK_INSN_C0_BTEST,    FMT_ADDR_BIT5,   dt_dword  },
    { 0xC8, KIRK_INSN_C8_BITSET,   FMT_ADDR_BIT5,   dt_dword  },
    { 0xD0, KIRK_INSN_D0_BITCLEAR, FMT_ADDR_BIT5,   dt_dword  },

    // 0xDA..0xDB: Zero Flag Clear / Set (top = 0x1B)
    { 0xDA, KIRK_INSN_DA_CLRZ,     FMT_NOOPS,       dt_dword  },
    { 0xDB, KIRK_INSN_DB_SETZ,     FMT_NOOPS,       dt_dword  },

    // 0xE0..0xE4: Unsigned Conditional & Unconditional Branches (top = 0x1C, cond = 0..4)
    { 0xE0, KIRK_INSN_E0_B,        FMT_BRANCH,      dt_code   },
    { 0xE1, KIRK_INSN_E1_BNZ,      FMT_BRANCH,      dt_code   },
    { 0xE2, KIRK_INSN_E2_BZ,       FMT_BRANCH,      dt_code   },
    { 0xE3, KIRK_INSN_E3_BHI,      FMT_BRANCH,      dt_code   },
    { 0xE4, KIRK_INSN_E4_BLO,      FMT_BRANCH,      dt_code   },

    // 0xE8: Subroutine Call (top = 0x1D)
    { 0xE8, KIRK_INSN_E8_CALL,     FMT_BRANCH,      dt_code   },

    // 0xF0: Subroutine Return (top = 0x1E)
    { 0xF0, KIRK_INSN_F0_RET,      FMT_NOOPS,       dt_dword  },

    // 0xF8: Wait-For-Event Hardware Accelerator Barrier (top = 0x1F)
    { 0xF8, KIRK_INSN_F8_WFE,      FMT_INTR,        dt_dword  },
};

static const kirk_opcode_desc_t* find_opcode_desc(uint8 opcode)
{
    for (size_t i = 0; i < qnumber(OpcodeTable); ++i)
    {
        if (OpcodeTable[i].opcode == opcode)
            return &OpcodeTable[i];
    }
    return nullptr;
}

static void set_mem_op(op_t& op, ea_t addr, KIRK_OPERAND_TYPE ktype, op_dtype_t dtype, char offb = 0)
{
    op.type = o_mem;
    op.dtype = dtype;
    op.kirk_type = ktype;
    op.addr = addr;
    op.offb = offb;
}

static void set_imm_op(op_t& op, uval_t value, KIRK_OPERAND_TYPE ktype, op_dtype_t dtype, char offb = 0)
{
    op.type = o_imm;
    op.dtype = dtype;
    op.kirk_type = ktype;
    op.value = value;
    op.offb = offb;
}

/* Analyze the current instruction. */
int kirk_t::kirk_ana(insn_t* _insn)
{
    insn_t& ida_insn = *_insn;
    INSN insn = get_dword(ida_insn.ea);
    uint8 opcode = static_cast<uint8>(f_opcode(insn));

    const kirk_opcode_desc_t* desc = find_opcode_desc(opcode);
    if (desc == nullptr)
    {
        ida_insn.itype = KIRK_INSN_X_INVALID;
        ida_insn.size = 0;
        return 0;
    }

    ida_insn.itype = desc->itype;
    kirk_format_t fmt = desc->format;
    op_dtype_t dtype = desc->dtype;

    switch (fmt)
    {
    case FMT_NOOPS:
        ida_insn.size = 4;
        return 4;

    case FMT_ADDR:
        set_mem_op(ida_insn.Op1, f_addr1(insn), KIRK_OPERAND_MEM_DIRECT, dtype, 1);
        ida_insn.size = 4;
        return 4;

    case FMT_ADDR_SHIFT5:
    case FMT_ADDR_BIT5:
    {
        if ((insn & 0xFE0) != 0)
        {
            ida_insn.itype = KIRK_INSN_X_INVALID;
            ida_insn.size = 0;
            return 0;
        }
        KIRK_OPERAND_TYPE imm_ktype = (fmt == FMT_ADDR_BIT5)
            ? KIRK_OPERAND_BIT_INDEX
            : KIRK_OPERAND_UIMM;
        set_mem_op(ida_insn.Op1, f_addr1(insn), KIRK_OPERAND_MEM_DIRECT, dtype, 1);
        set_imm_op(ida_insn.Op2, insn & 0x1F, imm_ktype, dt_dword, 2);
        ida_insn.size = 4;
        return 4;
    }

    case FMT_ADDR_IMM12:
        set_mem_op(ida_insn.Op1, f_addr1(insn), KIRK_OPERAND_MEM_DIRECT, dtype, 1);
        set_imm_op(ida_insn.Op2, f_imm2(insn), KIRK_OPERAND_UIMM, dt_dword, 2);
        ida_insn.size = 4;
        return 4;

    case FMT_ADDR_DATA:
    case FMT_IND_DATA:
    {
        uint32 data = get_dword(ida_insn.ea + 4);
        KIRK_OPERAND_TYPE dst_ktype = (fmt == FMT_IND_DATA)
            ? KIRK_OPERAND_MEM_INDIRECT
            : KIRK_OPERAND_MEM_DIRECT;
        set_mem_op(ida_insn.Op1, f_addr1(insn), dst_ktype, dtype, 1);
        set_imm_op(ida_insn.Op2, data, KIRK_OPERAND_UIMM, dt_dword, 4);

        refinfo_t ri;
        if (get_refinfo(&ri, ida_insn.ea, 1))
        {
            ea_t target, base;
            calc_reference_data(&target, &base, ida_insn.ea, ri, (static_cast<ea_t>(data) << 2) | KIRK_RAM_BASE);
            set_mem_op(ida_insn.Op2, target, KIRK_OPERAND_MEM_DIRECT, dt_dword, 4);
        }

        ida_insn.size = 8;
        return 8;
    }

    case FMT_ADDR_ADDR:
    case FMT_IND_ADDR:
    case FMT_ADDR_IND:
    case FMT_IND_IND:
    {
        KIRK_OPERAND_TYPE dst_ktype = (fmt == FMT_IND_ADDR || fmt == FMT_IND_IND)
            ? KIRK_OPERAND_MEM_INDIRECT
            : KIRK_OPERAND_MEM_DIRECT;
        KIRK_OPERAND_TYPE src_ktype = (fmt == FMT_ADDR_IND || fmt == FMT_IND_IND)
            ? KIRK_OPERAND_MEM_INDIRECT
            : KIRK_OPERAND_MEM_DIRECT;

        set_mem_op(ida_insn.Op1, f_addr2(insn), dst_ktype, dtype, 2);
        set_mem_op(ida_insn.Op2, f_addr1(insn), src_ktype, dtype, 1);
        ida_insn.size = 4;
        return 4;
    }

    case FMT_BRANCH:
    {
        ea_t branch = f_branch(insn);
        // Handle _reset (0x0000: E0001000) decap bit shift where target word 0x001 is in f_imm1
        if (opcode == 0xE0 && branch == 0 && f_imm1(insn) == 1 && ida_insn.ea == 0)
            branch = static_cast<ea_t>(f_imm1(insn)) << 2;

        ida_insn.Op1.type = o_near;
        ida_insn.Op1.dtype = dt_code;
        ida_insn.Op1.kirk_type = KIRK_OPERAND_BRANCH;
        ida_insn.Op1.addr = branch;
        ida_insn.Op1.offb = 2;
        ida_insn.size = 4;
        return 4;
    }

    case FMT_INTR:
        set_imm_op(ida_insn.Op1, f_mask24(insn), KIRK_OPERAND_INTR_MASK, dt_dword, 1);
        ida_insn.size = 4;
        return 4;

    default:
        ida_insn.itype = KIRK_INSN_X_INVALID;
        ida_insn.size = 0;
        return 0;
    }
}
