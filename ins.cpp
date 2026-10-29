/* KIRK IDP instructions - (c) Proxima 2023
*/

#include "kirk.hpp"

instruc_t Instructions[] =
{
    { "",            0                                      }, // 00: unknown
    { "--invalid--", 0                                      }, // 01: --invalid--
    { "store",       CF_CHG1 | CF_USE2                      }, // 0x09: store       (dst), imm32
    { "storea",      CF_CHG1 | CF_USE1 | CF_USE2            }, // 0x0A: storea      [(dst)], imm32
    { "mov32",       CF_CHG1 | CF_USE2                      }, // 0x0B: mov32       (dst), (src)
    { "mov32ia",     CF_CHG1 | CF_USE1 | CF_USE2            }, // 0x0C: mov32ia     [(dst)], (src)
    { "mov32a",      CF_CHG1 | CF_USE2                      }, // 0x0D: mov32a      (dst), [(src)]
    { "mov32aa",     CF_CHG1 | CF_USE1 | CF_USE2            }, // 0x0E: mov32aa     [(dst)], [(src)]
    { "cmpi",        CF_USE1 | CF_USE2                      }, // 0x11: cmpi        (dst), imm32
    { "cmpia",       CF_USE1 | CF_USE2                      }, // 0x12: cmpia       [(dst)], imm32
    { "cmpa",        CF_USE1 | CF_USE2                      }, // 0x13: cmpa        (dst), (src)
    { "cmpaa",       CF_USE1 | CF_USE2                      }, // 0x16: cmpaa       [(dst)], [(src)]
    { "addi",        CF_CHG1 | CF_USE1 | CF_USE2            }, // 0x19: addi        (dst), imm32
    { "adda",        CF_CHG1 | CF_USE1 | CF_USE2            }, // 0x1B: adda        (dst), (src)
    { "addc",        CF_CHG1 | CF_USE1 | CF_USE2            }, // 0x21: addc        (dst), imm32
    { "subi",        CF_CHG1 | CF_USE1 | CF_USE2            }, // 0x29: subi        (dst), imm32
    { "andi",        CF_CHG1 | CF_USE1 | CF_USE2            }, // 0x39: andi        (dst), imm32
    { "andia",       CF_CHG1 | CF_USE1 | CF_USE2            }, // 0x3A: andia       [(dst)], imm32
    { "ori",         CF_CHG1 | CF_USE1 | CF_USE2            }, // 0x41: ori         (dst), imm32
    { "or",          CF_CHG1 | CF_USE1 | CF_USE2            }, // 0x43: or          (dst), (src)
    { "ora",         CF_CHG1 | CF_USE1 | CF_USE2            }, // 0x44: ora         [(dst)], (src)
    { "xori",        CF_CHG1 | CF_USE1 | CF_USE2            }, // 0x49: xori        (dst), imm32
    { "xora",        CF_CHG1 | CF_USE1 | CF_USE2            }, // 0x4B: xora        (dst), (src)
    { "xoraa",       CF_CHG1 | CF_USE1 | CF_USE2            }, // 0x4E: xoraa       [(dst)], [(src)]
    { "mov128",      CF_CHG1 | CF_USE2                      }, // 0x53: mov128      (dst), (src)
    { "inc32",       CF_CHG1 | CF_USE1                      }, // 0x80: inc32       (dst)
    { "dec32",       CF_CHG1 | CF_USE1                      }, // 0x88: dec32       (dst)
    { "lsh",         CF_SHFT | CF_CHG1 | CF_USE1 | CF_USE2  }, // 0x90: lsh         (dst), shift5
    { "rsh",         CF_SHFT | CF_CHG1 | CF_USE1 | CF_USE2  }, // 0x98: rsh         (dst), shift5
    { "setmode",     CF_CHG1 | CF_USE2                      }, // 0xA0: setmode     (dst), imm12
    { "byteswap",    CF_CHG1 | CF_USE1                      }, // 0xB0: byteswap    (dst)
    { "btest",       CF_USE1 | CF_USE2                      }, // 0xC0: btest       (src), bit5
    { "bitset",      CF_CHG1 | CF_USE1 | CF_USE2            }, // 0xC8: bitset      (dst), bit5
    { "bitclear",    CF_CHG1 | CF_USE1 | CF_USE2            }, // 0xD0: bitclear    (dst), bit5
    { "clrz",        0                                      }, // 0xDA: clrz
    { "setz",        0                                      }, // 0xDB: setz
    { "b",           CF_USE1 | CF_STOP | CF_JUMP            }, // 0xE0: b           target
    { "bnz",         CF_USE1 | CF_JUMP                      }, // 0xE1: bnz         target
    { "bz",          CF_USE1 | CF_JUMP                      }, // 0xE2: bz          target
    { "bhi",         CF_USE1 | CF_JUMP                      }, // 0xE3: bhi         target
    { "blo",         CF_USE1 | CF_JUMP                      }, // 0xE4: blo         target
    { "call",        CF_USE1 | CF_CALL                      }, // 0xE8: call        target
    { "ret",         CF_STOP                                }, // 0xF0: ret
    { "wfe",         CF_USE1                                }, // 0xF8: wfe         mask24
};

CASSERT(qnumber(Instructions) == KIRK_INSN_LAST);
