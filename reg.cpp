/* KIRK IDP main and reg - (c) Proxima 2023
*/

#pragma warning ( disable : 4146)
#include "kirk.hpp"

int data_id;

//---------------------------------------------------------------------------------------------------------------------
static bool idaapi can_have_type(const op_t& x)
{
    switch (x.type)
    {
    case o_void:
    case o_reg:
    case o_near:
        return false;
    default:
        return true;
    }
}

//---------------------------------------------------------------------------------------------------------------------
ssize_t idaapi idb_listener_t::on_event(ssize_t, va_list)
{
    return 0;
}

//---------------------------------------------------------------------------------------------------------------------
// This old-style callback only returns the processor module object.
static ssize_t idaapi notify(void*, int msgid, va_list)
{
    if (msgid == processor_t::ev_get_procmod)
        return size_t(SET_MODULE_DATA(kirk_t));

    return 0;
}

void kirk_t::load_from_idb()
{
    ioh.restore_device(IORESP_NONE);
    if (ioh.ports.empty() && ioh.device.empty())
    {
        ioh.device = "KIRK";
        ioh.apply_config_file(IORESP_NONE);
    }
}

//---------------------------------------------------------------------------------------------------------------------
const char* kirk_t::find_ioport_bit_name(ea_t port, size_t bit) const
{
    const ioport_bit_t* b = find_ioport_bit(ioh.ports, port, bit);
    if (b != nullptr && !b->name.empty())
        return b->name.c_str();

    return nullptr;
}

//---------------------------------------------------------------------------------------------------------------------
bool kirk_t::kirk_find_ioport_bit(outctx_t& ctx, ea_t port, size_t bit)
{
    const char* name = find_ioport_bit_name(port, bit);
    if (name != nullptr)
    {
        ctx.out_line(name, COLOR_IMPNAME);
        return true;
    }

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
        ioh.get_cfg_filename(cfgfile, sizeof(cfgfile));
        iohandler_t::parse_area_line0_t cb(ioh);
        if (choose_ioport_device2(&ioh.device, cfgfile, &cb))
            ioh.set_device_name(ioh.device.c_str(), IORESP_ALL);
        break;
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
        // Set big-endian mode of the IDA kernel
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
    "'\"",         // special symbols in char and string constants

    ".ascii",      // ascii string directive
    ".byte",       // byte directive
    ".word",       // word directive
    ".dword",      // dword  (4 bytes)
    ".qword",      // qword  (8 bytes)
    ".oword",      // oword  (16 bytes)
    ".float",      // float  (4 bytes)
    ".double",     // double (8 bytes)
    NULL,          // tbyte  (10/12 bytes)
    NULL,          // packed decimal real
    "#d dup(#v)",  // array keyword (#h,#d,#v,#s(...))
    ".block %s",   // uninited arrays
    ".equ",        // equ
    NULL,          // seg prefix
    NULL,          // comment close
    NULL,          // low 8 bits
    NULL,          // high 8 bits
    NULL,          // low 16 bits
    NULL,          // high 16 bits
    NULL,          // preline
    NULL,          // start of bold text
    NULL,          // start of normal text
    NULL,          // start of literal text
    NULL,          // end of comment
    NULL,          // get_type_name
    NULL,          // align
    NULL,          // left brace
    NULL,          // right brace
    NULL,          // modulo operator
    NULL,          // and operator
    NULL,          // or operator
    NULL,          // xor operator
    NULL,          // not operator
    NULL,          // shift left operator
    NULL,          // shift right operator
    NULL           // sizeof operator
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

//-----------------------------------------------------------------------
//      Processor Definition
//-----------------------------------------------------------------------

#define PLFM_KIRK (0x8000 + 0x1701)

static const char* const RegNames[] =
{
    "cs",
    "ds",
};

processor_t LPH =
{
    IDP_INTERFACE_VERSION,   // version
    PLFM_KIRK,               // id
    // flag
    PR_USE32 | PR_DEFSEG32 | PRN_HEX | PR_RNAMESOK | PR_ALIGN,

    0,                       // flag2
    8,                       // 8 bits in a byte for code segments
    8,                       // 8 bits in a byte for other segments

    shnames,
    lnames,

    asms,

    notify,

    RegNames,
    qnumber(RegNames),       // number of registers

    0,                       // first segment register
    1,                       // last segment register
    0,                       // size of a segment register
    0,                       // virtual CS
    1,                       // virtual DS

    NULL,                    // no known code start sequences
    retcodes,                // 'Return' instruction codes

    0,                       // first instruction
    KIRK_INSN_LAST,          // last instruction
    Instructions,            // instruc
    0,                       // int tbyte_size;  -- doesn't exist
    { 0, 0, 0, 0 },          // char real_width[4];
    KIRK_INSN_F0_RET,        // icode of return instruction
};
