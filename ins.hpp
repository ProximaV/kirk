/* KIRK IDP instructions - (c) Proxima 2023
*/

#ifndef __INSTRS_HPP
#define __INSTRS_HPP

extern instruc_t Instructions[];

typedef enum nameNum ENUM_SIZE(uint16)
{
        KIRK_INSN_UNKNOWN = 0,
        KIRK_INSN_X_INVALID,
        KIRK_INSN_09_STORE,
        KIRK_INSN_0B_MOV32,
        KIRK_INSN_0D_MOV32A,
        KIRK_INSN_0E_MOV32AA,
        KIRK_INSN_11_CMPI,
        KIRK_INSN_12_CMPPLUS,
        KIRK_INSN_13_CMPA,
        KIRK_INSN_16_SUBA,
        KIRK_INSN_19_ADDI,
        KIRK_INSN_1B_ADDA,
        KIRK_INSN_21,
        KIRK_INSN_29_SUBI,
        KIRK_INSN_39_ANDI,
        KIRK_INSN_3A_ANDA,
        KIRK_INSN_43_MOV16,
        KIRK_INSN_44_ORA,
        KIRK_INSN_49_XORI,
        KIRK_INSN_4B_XORA,
        KIRK_INSN_53_MOV128,
        KIRK_INSN_80_INC32,
        KIRK_INSN_88_DEC32,
        KIRK_INSN_90_LSH,
        KIRK_INSN_98_NAND,
        KIRK_INSN_A0_SETMODE,
        KIRK_INSN_B0_BYTESWAP,
        KIRK_INSN_C0_TEST,
        KIRK_INSN_C8_BITSET,
        KIRK_INSN_D0_BITCLEAR,
        KIRK_INSN_DA_CLRZ,
        KIRK_INSN_DB_SETZ,
        KIRK_INSN_E0_B,
        KIRK_INSN_E1_BNZ,
        KIRK_INSN_E2_BZ,
        KIRK_INSN_E3_BGT,
        KIRK_INSN_E4_BLT,
        KIRK_INSN_E8_CALL,
        KIRK_INSN_E9_CALL2,
        KIRK_INSN_F0_RET,
        KIRK_INSN_F8_INTR,
}KIRK_INSN_TYPE;
#endif
