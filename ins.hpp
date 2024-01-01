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
        KIRK_INSN_0D,
        KIRK_INSN_0E,
        KIRK_INSN_11_CMP,
        KIRK_INSN_12,
        KIRK_INSN_13,
        KIRK_INSN_16,
        KIRK_INSN_19_ADD,
        KIRK_INSN_1B_INC,
        KIRK_INSN_21,
        KIRK_INSN_29_SUB,
        KIRK_INSN_39_OR,
        KIRK_INSN_3A_AND,
        KIRK_INSN_43,
        KIRK_INSN_44,
        KIRK_INSN_49,
        KIRK_INSN_4B,
        KIRK_INSN_53_MOV128,
        KIRK_INSN_80_INC32,
        KIRK_INSN_88_DEC32,
        KIRK_INSN_90_LSH,
        KIRK_INSN_98_NAND,
        KIRK_INSN_A0_SETMODE,
        KIRK_INSN_B0,
        KIRK_INSN_C0_TEST,
        KIRK_INSN_C8_BITSET,
        KIRK_INSN_D0_BITCLEAR,
        KIRK_INSN_DA,
        KIRK_INSN_DB,
        KIRK_INSN_E0_BRA,
        KIRK_INSN_E1_BNE,
        KIRK_INSN_E2_BEQ,
        KIRK_INSN_E3_BGT,
        KIRK_INSN_E4_BLT,
        KIRK_INSN_E8_CALL,
        KIRK_INSN_E9_CALL2,
        KIRK_INSN_F0_RET,
        KIRK_INSN_F8_hw_crypto_hash_dma,
}KIRK_INSN_TYPE;
#endif
