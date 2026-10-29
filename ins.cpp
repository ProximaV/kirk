/* KIRK IDP instructions - (c) Proxima 2023
*/

#include "kirk.hpp"

instruc_t Instructions[] =
{
    { "",            0                                      }, // 00: unknown
    { "--invalid--", 0                                      }, // 01: --invalid--
    { "mov",         CF_CHG1 | CF_USE2                      }, // 0x09: mov     (dst), imm32
    { "mov",         CF_CHG1 | CF_USE1 | CF_USE2            }, // 0x0A: mov     [(dst)], imm32
    { "mov",         CF_CHG1 | CF_USE2                      }, // 0x0B: mov     (dst), (src)
    { "mov",         CF_CHG1 | CF_USE1 | CF_USE2            }, // 0x0C: mov     [(dst)], (src)
    { "mov",         CF_CHG1 | CF_USE2                      }, // 0x0D: mov     (dst), [(src)]
    { "mov",         CF_CHG1 | CF_USE1 | CF_USE2            }, // 0x0E: mov     [(dst)], [(src)]
    { "cmp",         CF_USE1 | CF_USE2                      }, // 0x11: cmp     (dst), imm32
    { "cmp",         CF_USE1 | CF_USE2                      }, // 0x12: cmp     [(dst)], imm32
    { "cmp",         CF_USE1 | CF_USE2                      }, // 0x13: cmp     (dst), (src)
    { "cmp",         CF_USE1 | CF_USE2                      }, // 0x16: cmp     [(dst)], [(src)]
    { "add",         CF_CHG1 | CF_USE1 | CF_USE2            }, // 0x19: add     (dst), imm32
    { "add",         CF_CHG1 | CF_USE1 | CF_USE2            }, // 0x1B: add     (dst), (src)
    { "addc",        CF_CHG1 | CF_USE1 | CF_USE2            }, // 0x21: addc    (dst), imm32
    { "sub",         CF_CHG1 | CF_USE1 | CF_USE2            }, // 0x29: sub     (dst), imm32
    { "and",         CF_CHG1 | CF_USE1 | CF_USE2            }, // 0x39: and     (dst), imm32
    { "and",         CF_CHG1 | CF_USE1 | CF_USE2            }, // 0x3A: and     [(dst)], imm32
    { "or",          CF_CHG1 | CF_USE1 | CF_USE2            }, // 0x41: or      (dst), imm32
    { "or",          CF_CHG1 | CF_USE1 | CF_USE2            }, // 0x43: or      (dst), (src)
    { "or",          CF_CHG1 | CF_USE1 | CF_USE2            }, // 0x44: or      [(dst)], (src)
    { "xor",         CF_CHG1 | CF_USE1 | CF_USE2            }, // 0x49: xor     (dst), imm32
    { "xor",         CF_CHG1 | CF_USE1 | CF_USE2            }, // 0x4B: xor     (dst), (src)
    { "xor",         CF_CHG1 | CF_USE1 | CF_USE2            }, // 0x4E: xor     [(dst)], [(src)]
    { "mov128",      CF_CHG1 | CF_USE2                      }, // 0x53: mov128  (dst), (src)
    { "inc",         CF_CHG1 | CF_USE1                      }, // 0x80: inc     (dst)
    { "dec",         CF_CHG1 | CF_USE1                      }, // 0x88: dec     (dst)
    { "lsl",         CF_SHFT | CF_CHG1 | CF_USE1 | CF_USE2  }, // 0x90: lsl     (dst), shift5
    { "lsr",         CF_SHFT | CF_CHG1 | CF_USE1 | CF_USE2  }, // 0x98: lsr     (dst), shift5
    { "iocmd",       CF_CHG1 | CF_USE2                      }, // 0xA0: iocmd   (ctrl), imm12
    { "bswap",       CF_CHG1 | CF_USE1                      }, // 0xB0: bswap   (dst)
    { "btst",        CF_USE1 | CF_USE2                      }, // 0xC0: btst    (src), bit5
    { "bset",        CF_CHG1 | CF_USE1 | CF_USE2            }, // 0xC8: bset    (dst), bit5
    { "bclr",        CF_CHG1 | CF_USE1 | CF_USE2            }, // 0xD0: bclr    (dst), bit5
    { "clrt",        0                                      }, // 0xDA: clrt
    { "sett",        0                                      }, // 0xDB: sett
    { "b",           CF_USE1 | CF_STOP | CF_JUMP            }, // 0xE0: b       target
    { "bf",          CF_USE1 | CF_JUMP                      }, // 0xE1: bf      target
    { "bt",          CF_USE1 | CF_JUMP                      }, // 0xE2: bt      target
    { "bhi",         CF_USE1 | CF_JUMP                      }, // 0xE3: bhi     target
    { "blo",         CF_USE1 | CF_JUMP                      }, // 0xE4: blo     target
    { "call",        CF_USE1 | CF_CALL                      }, // 0xE8: call    target
    { "ret",         CF_STOP                                }, // 0xF0: ret
    { "wfe",         CF_USE1                                }, // 0xF8: wfe     mask24
};

CASSERT(qnumber(Instructions) == KIRK_INSN_LAST);
