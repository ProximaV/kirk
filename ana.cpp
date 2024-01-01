/* KIRK IDP analysis - (c) Proxima 2023
*/
#pragma warning (disable : 4146)
#include "kirk.hpp"

typedef unsigned int INSN;

int rambase = 0xE0000000;

int f_opcode(INSN insn) { return (insn >> 24) & 0xFF; }
int f_addr1(INSN insn) { return (((insn >> 12) & 0xFFF) << 2) | rambase; }
int f_addr2(INSN insn) { return ((insn  & 0xFFF) << 2) | rambase; }
int f_imm1(INSN insn) { return (insn >> 12) & 0xFFF; }
int f_imm2(INSN insn) { return insn & 0xFFF; }
int f_branch(INSN insn) { return ((insn & 0xFFF) << 2); }

/* Analyze the current instruction. */
int kirk_t::kirk_ana(insn_t* _insn)
{
    insn_t& ida_insn = *_insn;
    KIRK_INSN_TYPE itype;
    INSN insn;
    unsigned int data;


    insn = get_dword(ida_insn.ea);
    
    int opcode = f_opcode(insn);
    switch (opcode)
    {
    case 0x09://store             ($addr1),$data  
        data = get_dword(ida_insn.ea + 4);
        itype = KIRK_INSN_09_STORE; goto decode_insn_format_addr_data;
        break;
    case 0x0B://op0B            ($addr1), ($addr1)
        itype = KIRK_INSN_0B_MOV32; goto decode_insn_format_addr_addr;
        break;
    case 0x0D://op0D            ($addr1), ($addr1)
        itype = KIRK_INSN_0D; goto decode_insn_format_addr_addr;
        break;
    case 0x0E://op0E            ($addr1), ($addr1)      
        itype = KIRK_INSN_0E; goto decode_insn_format_addr_addr;
        break;
    case 0x11://cmp            ($addr1),$data
        data = get_dword(ida_insn.ea + 4);
        itype = KIRK_INSN_11_CMP; goto decode_insn_format_addr_data;
        break;
    case 0x12://op12          ($addr1),$data
        data = get_dword(ida_insn.ea + 4);
        itype = KIRK_INSN_12; goto decode_insn_format_addr_data;
        break;
    case 0x13://op13            ($addr1), ($addr1)      
        itype = KIRK_INSN_13; goto decode_insn_format_addr_addr;
        break;
    case 0x16://op16            ($addr1), ($addr1)      
        itype = KIRK_INSN_16; goto decode_insn_format_addr_addr;
        break;
    case 0x19://op19             ($addr1),$data 
        data = get_dword(ida_insn.ea + 4);
        itype = KIRK_INSN_19_ADD; goto decode_insn_format_addr_data;
        break;
    case 0x1B://op1B            ($addr1), ($addr1)      
        itype = KIRK_INSN_1B_INC; goto decode_insn_format_addr_addr;
        break;
    case 0x21://op21             ($addr1),$data 
        data = get_dword(ida_insn.ea + 4);
        itype = KIRK_INSN_21; goto decode_insn_format_addr_data;
        break;
    case 0x29://op29             ($addr1),$data 
        data = get_dword(ida_insn.ea + 4);
        itype = KIRK_INSN_29_SUB; goto decode_insn_format_addr_data;
        break;
    case 0x39://op39             ($addr1),$data 
        data = get_dword(ida_insn.ea + 4);
        itype = KIRK_INSN_39_OR; goto decode_insn_format_addr_data;
        break;
    case 0x3A://and             ($addr1),$data 
        data = get_dword(ida_insn.ea + 4);
        itype = KIRK_INSN_3A_AND; goto decode_insn_format_addr_data;
        break;
    case 0x43://op43            ($addr1), ($addr1)      
        itype = KIRK_INSN_43; goto decode_insn_format_addr_addr;
        break;
    case 0x44://op44            ($addr1), ($addr1)      
        itype = KIRK_INSN_44; goto decode_insn_format_addr_addr;
        break;
    case 0x49://op49             ($addr1),$data 
        data = get_dword(ida_insn.ea + 4);
        itype = KIRK_INSN_49; goto decode_insn_format_addr_data;
        break;
    case 0x4B://op4B            ($addr1), ($addr1)      
        itype = KIRK_INSN_4B; goto decode_insn_format_addr_addr;
        break;
    case 0x53://op53            ($addr1), ($addr1)      
        itype = KIRK_INSN_53_MOV128; goto decode_insn_format_addr_addr;
        break;
    case 0x80://op80            ($addr1), $imm      
        itype = KIRK_INSN_80_INC32; goto decode_insn_format_addr_imm;
        break;
    case 0x88://op88            ($addr1), $imm      
        itype = KIRK_INSN_88_DEC32; goto decode_insn_format_addr_imm;
        break;
    case 0x90://op90            ($addr1), $imm      
        itype = KIRK_INSN_90_LSH; goto decode_insn_format_addr_imm;
        break;
    case 0x98://op98            ($addr1), $imm      
        itype = KIRK_INSN_98_NAND; goto decode_insn_format_addr_imm;
        break;
    case 0xA0://opA0            ($addr1), $imm      
        itype = KIRK_INSN_A0_SETMODE; goto decode_insn_format_addr_imm;
        break;
    case 0xB0://opB0            ($addr1), $imm      
        itype = KIRK_INSN_B0; goto decode_insn_format_addr_imm;
        break;
    case 0xC0://test            ($addr1), $imm      
        itype = KIRK_INSN_C0_TEST; goto decode_insn_format_addr_imm;
        break;
    case 0xC8://opC8            ($addr1), $imm      
        itype = KIRK_INSN_C8_BITSET; goto decode_insn_format_addr_imm;
        break;
    case 0xD0://opD0            ($addr1), $imm      
        itype = KIRK_INSN_D0; goto decode_insn_format_addr_imm;
        break;
    case 0xDA://opDA            $imm, $imm      
        itype = KIRK_INSN_DA; goto decode_insn_format_imm_imm;
        break;
    case 0xDB://opDB            $imm, $imm      
        itype = KIRK_INSN_DB; goto decode_insn_format_imm_imm;
        break;
    case 0xE0://bra            $branch     
        itype = KIRK_INSN_E0_BRA; goto decode_insn_format_branch;
        break;
    case 0xE1://bne            $branch     
        itype = KIRK_INSN_E1_BNE; goto decode_insn_format_branch;
        break;
    case 0xE2://beq            $branch     
        itype = KIRK_INSN_E2_BEQ; goto decode_insn_format_branch;
        break;
    case 0xE3://bge            $branch     
        itype = KIRK_INSN_E3_BGT; goto decode_insn_format_branch;
        break;
    case 0xE4://ble            $branch     
        itype = KIRK_INSN_E4_BLT; goto decode_insn_format_branch;
        break;
    case 0xE8://call            $branch     
        itype = KIRK_INSN_E8_CALL; goto decode_insn_format_branch;
        break;
    case 0xE9://call2            $branch     
        itype = KIRK_INSN_E9_CALL2; goto decode_insn_format_branch;
        break;
    case 0xF0://ret              
        itype = KIRK_INSN_F0_RET; goto decode_insn_format_ret;
        break;
    case 0xF8://opF8            $imm, $imm      
        itype = KIRK_INSN_F8_hw_crypto_hash_dma; goto decode_insn_format_imm_imm;
        break;
    default:
        itype = KIRK_INSN_X_INVALID; goto decode_insn_format_empty;
        break;
    }
                                                     
    /* The instruction has been decoded, now extract the fields. */
decode_insn_format_empty:
    {
        ida_insn.itype = itype;
        ida_insn.size = 0;
        return 0;
    }
decode_insn_format_ret:
    {
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_addr_data:
    {
        
        int addr1 = f_addr1(insn);

        ida_insn.Op1.type = o_mem;
        ida_insn.Op1.kirk_type = KIRK_OPERAND_MEM;
        ida_insn.Op1.addr = addr1;
        ida_insn.Op2.type = o_imm;
        ida_insn.Op2.kirk_type = KIRK_OPERAND_UIMM;
        ida_insn.Op2.value = data;
        ida_insn.itype = itype;
        ida_insn.size = 8;
        return 8;
    }
decode_insn_format_addr_addr:
    {
        int addr1 = f_addr1(insn);
        int addr2 = f_addr2(insn);

        ida_insn.Op1.type = o_mem;
        ida_insn.Op1.kirk_type = KIRK_OPERAND_MEM;
        ida_insn.Op1.addr = addr1;
        ida_insn.Op2.type = o_mem;
        ida_insn.Op2.kirk_type = KIRK_OPERAND_MEM;
        ida_insn.Op2.addr = addr2;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_addr_imm:
    {
        int addr1 = f_addr1(insn);
        int imm2 = f_imm2(insn);

        ida_insn.Op1.type = o_mem;
        ida_insn.Op1.kirk_type = KIRK_OPERAND_MEM;
        ida_insn.Op1.addr = addr1;
        ida_insn.Op2.type = o_imm;
        ida_insn.Op2.kirk_type = KIRK_OPERAND_UIMM;
        ida_insn.Op2.value = imm2;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_imm_imm:
    {
        int imm1 = f_imm1(insn);
        int imm2 = f_imm2(insn);

        ida_insn.Op1.type = o_imm;
        ida_insn.Op1.kirk_type = KIRK_OPERAND_UIMM;
        ida_insn.Op1.value = imm1;
        ida_insn.Op2.type = o_imm;
        ida_insn.Op2.kirk_type = KIRK_OPERAND_UIMM;
        ida_insn.Op2.value = imm2;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }
decode_insn_format_branch:
    {
        int branch = f_branch(insn);

        ida_insn.Op1.type = o_near;
        ida_insn.Op1.kirk_type = KIRK_OPERAND_BRANCH;
        ida_insn.Op1.addr = branch;
        ida_insn.itype = itype;
        ida_insn.size = 4;
        return 4;
    }

}