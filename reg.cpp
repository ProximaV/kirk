/* KIRK IDP main and reg - (c) Proxima 2023
*/

#pragma warning ( disable : 4146)
#include "kirk.hpp"

int data_id;

//---------------------------------------------------------------------------------------------------------------------
static bool idaapi can_have_type(const op_t& x) // returns 1 - operand can have
{
    switch (x.type)
    {
    case o_void:
    case o_reg:
    case o_near:
        return 0;
        //case o_phrase: can have type because of ASI or 0 struct offsets
    }

    return 1;
}

//---------------------------------------------------------------------------------------------------------------------
ssize_t idaapi idb_listener_t::on_event(ssize_t code, va_list)
{
    /*
    switch (code)
    {
        // add stuff here...
        default: break;
    }
    */

    return 0;
}

//---------------------------------------------------------------------------------------------------------------------
// This old-style callback only returns the processor module object.
static ssize_t idaapi notify(void*, int msgid, va_list)
{
    if (msgid == processor_t::ev_get_procmod) return size_t(SET_MODULE_DATA(kirk_t));

    return 0;
}

void kirk_t::load_from_idb()
{
    ioh.restore_device();
}

//---------------------------------------------------------------------------------------------------------------------
bool kirk_t::kirk_find_ioport_bit(outctx_t& ctx, int port, int bit)
{
    const ioport_bit_t* b = find_ioport_bit(ioh.ports, port, bit);
    if (b != nullptr && !b->name.empty()) ctx.out_line(b->name.c_str(), COLOR_IMPNAME); return true;

    return false;
}

//---------------------------------------------------------------------------------------------------------------------
ssize_t idaapi kirk_t::on_event(ssize_t msgid, va_list va)
{
    int code = 0;

    switch (msgid)
    {
    case processor_t::ev_newfile:
    {
        char cfgfile[QMAXFILE];
        //warning("In newfile");
        ioh.get_cfg_filename(cfgfile, sizeof(cfgfile));
        iohandler_t::parse_area_line0_t cb(ioh);
        if (choose_ioport_device2(&ioh.device, cfgfile, &cb))
            ioh.set_device_name(ioh.device.c_str(), IORESP_ALL);
    }
    case processor_t::ev_ending_undo:
    case processor_t::ev_oldfile:
    {
        load_from_idb();
        break;
    }
    case processor_t::ev_get_frame_retsize:
    {
        int* frsize = va_arg(va, int*);
        *frsize = 0;
        return 1;
    }
    case processor_t::ev_init:
    {
        hook_event_listener(HT_IDB, &idb_listener, &LPH);
        // Set a big endian mode of the IDA kernel
        inf_set_be(true);
        helper.create(PROCMOD_NODE_NAME);
        break;
    }
    case processor_t::ev_term:
    {
        unhook_event_listener(HT_IDB, &idb_listener);
        ioh.ports.clear();
        clr_module_data(data_id);
        break;
    }

    case processor_t::ev_ana_insn:
    {
        insn_t* out = va_arg(va, insn_t*);
        return kirk_ana(out);
    }
    case processor_t::ev_emu_insn:
    {
        const insn_t* insn = va_arg(va, const insn_t*);
        return kirk_emu(*insn) ? 1 : -1;
    }
    case processor_t::ev_out_insn:
    {
        outctx_t* ctx = va_arg(va, outctx_t*);
        out_insn(*ctx);
        return 1;
    }
    case processor_t::ev_out_operand:
    {
        outctx_t* ctx = va_arg(va, outctx_t*);
        const op_t* op = va_arg(va, const op_t*);
        return out_opnd(*ctx, *op) ? 1 : -1;
    }
    case processor_t::ev_can_have_type:
    {
        const op_t* op = va_arg(va, const op_t*);
        return can_have_type(*op) ? 1 : -1;
    }

    default:
        break;
    }
    va_end(va);

    return code;
}

//---------------------------------------------------------------------------------------------------------------------
static const asm_t kirkasm =
{
    ASH_HEXF3 | AS_COLON | ASB_BINF0 | ASO_OCTF1 | AS_NCMAS,
    0,
    "KIRK assembler",
    0,
    NULL,
    ".org",
    ".end",

    ";",           // comment string
    '"',           // string delimiter
    '\'',          // char delimiter (no char consts)
    "\\\"'",       // special symbols in char and string constants

    ".ascii",      // ascii string directive
    ".byte",       // byte directive
    ".word",       // word directive
    ".dword",      // dword  (4 bytes)
    ".qword",      // qword  (8 bytes)
    NULL,          // oword  (16 bytes)
    ".float"       // float  (4 bytes)
    ".double",     // double (8 bytes)
    NULL,          // tbyte  (10/12 bytes)
    NULL,          // packed decimal real
    NULL,          // arrays (#h,#d,#v,#s(...)
    ".block %s",   // uninited arrays
    ".equ",        // equ
    NULL,          // seg prefix
    //  preline, NULL, operdim,
    NULL, NULL, NULL,
    NULL,
    NULL,
    NULL,          // func_header
    NULL,          // func_footer
    NULL,          // public
    NULL,          // weak
    NULL,          // extrn
    NULL,          // comm
    NULL,          // get_type_name
    NULL,          // align
    0, 0,          // lbrace, rbrace
    NULL,          // mod
    NULL,          // and
    NULL,          // or
    NULL,          // xor
    NULL,          // not
    NULL,          // shl
    NULL,          // shr
    NULL,          // sizeof
};

//---------------------------------------------------------------------------------------------------------------------
static const asm_t* const asms[] = { &kirkasm, NULL };

//---------------------------------------------------------------------------------------------------------------------
static const uchar retcode_1[] = { 0xF0, 0x00, 0x00, 0x00 };


//---------------------------------------------------------------------------------------------------------------------
static const bytes_t retcodes[] =
{
    { sizeof(retcode_1), retcode_1 },
    { 0, NULL }
};

//---------------------------------------------------------------------------------------------------------------------
#define FAMILY "Star Trek PSP Processors:"
static const char* const shnames[] = { "KIRK", NULL };
static const char* const lnames[] = { FAMILY"KIRK big endian", NULL };

//---------------------------------------------------------------------------------------------------------------------

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------

#define PLFM_KIRK 0x8000 +0x1701
static const char* const RegNames[] =
{
    "r0",
    "r1",
    "r2",
    "r3",
    "r4",
    "gp",
    "fp",
    "sp",
    "ra",
    "ea",
    "ba",
};

processor_t LPH =
{
    IDP_INTERFACE_VERSION,   // version
    PLFM_KIRK,               // id
    // flag
    PR_USE32|PR_DEFSEG32|PRN_HEX|PR_RNAMESOK|PR_ALIGN,  

    0,                       // the module has processor-specific configuration options
    8,                       // 8 bits in a byte for code segments
    8,                       // 8 bits in a byte for other segments

    shnames,
    lnames,

    asms,

    notify,

    RegNames,
    qnumber(RegNames),       // number of registers

    qnumber(RegNames) - 2,     // first
    qnumber(RegNames) - 1,     // last
    0,                       // size of a segment register
    qnumber(RegNames) - 2,     // virtual CS
    qnumber(RegNames) - 1,     // virtual DS

    NULL,                    // no known code start sequences
    retcodes,                // 'Return' instruction codes

    0,                       // 
    KIRK_INSN_F8_hw_crypto_hash_dma + 1,         // 
    Instructions,            // instruc
    0,                       // int tbyte_size;  -- doesn't exist
    { 0, 0, 0, 0 },          // char real_width[4];
    // number of symbols after decimal point
    // 2byte float (0-does not exist)
    // normal float
    // normal double
    // long double
    KIRK_INSN_F0_RET,           // icode of return instruction. It is ok to give any of possible return instructions
};
