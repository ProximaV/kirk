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
        KIRK_INSN_19,
        KIRK_INSN_1B,
        KIRK_INSN_21,
        KIRK_INSN_29,
        KIRK_INSN_39,
        KIRK_INSN_3A_AND,
        KIRK_INSN_43,
        KIRK_INSN_44,
        KIRK_INSN_49,
        KIRK_INSN_4B,
        KIRK_INSN_53_MOV128,
        KIRK_INSN_80,
        KIRK_INSN_88,
        KIRK_INSN_90,
        KIRK_INSN_98,
        KIRK_INSN_A0,
        KIRK_INSN_B0,
        KIRK_INSN_C0_TEST,
        KIRK_INSN_C8,
        KIRK_INSN_D0,
        KIRK_INSN_DA,
        KIRK_INSN_DB,
        KIRK_INSN_E0_BRA,
        KIRK_INSN_E1_BNE,
        KIRK_INSN_E2_BEQ,
        KIRK_INSN_E3_BGE,
        KIRK_INSN_E4_BLE,
        KIRK_INSN_E8_CALL,
        KIRK_INSN_E9_CALL2,
        KIRK_INSN_F0_RET,
        KIRK_INSN_F8,
}KIRK_INSN_TYPE;
#endif
