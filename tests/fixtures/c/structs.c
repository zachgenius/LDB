/*
 * Test fixture for LDB endpoint tests.
 *
 * Built with -g -O0 so DWARF is present and unoptimized. Struct layouts
 * here are deterministic on x86-64 / arm64 with the default ABI:
 *
 *   struct point2          : 8 bytes, no padding.
 *   struct stride_pad      : 8 bytes, 3-byte hole between tag and value.
 *   struct nested          : 16 bytes, no internal padding (origin at 0,
 *                            scale at 8 since double is 8-aligned).
 *   struct dxp_login_frame : 16 bytes, 4-byte hole between magic and sid.
 *
 * If a future compiler/ABI invalidates these, regenerate the test
 * expectations rather than working around them — the goal is fidelity.
 */

#include <stdint.h>

struct point2 {
    int x;
    int y;
};

struct stride_pad {
    char tag;
    int  value;
};

struct nested {
    struct point2 origin;
    double        scale;
};

/* Mirrors the DXP login frame the user's RE workflow targets: 4-byte
 * magic followed by an 8-byte session id, with a 4-byte alignment hole. */
struct dxp_login_frame {
    uint32_t magic;
    uint64_t sid;
};

/* Rodata strings — string.list / string.xref will look for these. */
const char *const k_schema_name   = "btp_schema.xml";
const char *const k_protocol_name = "DXP/1.0";

/* Globals — symbol.find target. */
struct point2          g_origin         = { 0, 0 };
struct dxp_login_frame g_login_template = { 0xDEADBEEFu, 0xCAFEBABE12345678ULL };

/* Functions — symbol.find / disasm targets. */
int point2_distance_sq(const struct point2 *a, const struct point2 *b) {
    int dx = a->x - b->x;
    int dy = a->y - b->y;
    return dx * dx + dy * dy;
}

int main(void) {
    /* Reference every symbol so dead-code elimination doesn't drop them. */
    struct nested     n = { { 1, 2 }, 3.14 };
    struct stride_pad s = { 'x', 42 };
    int               d = point2_distance_sq(&g_origin, &n.origin);

    volatile const char *p1 = k_schema_name;
    volatile const char *p2 = k_protocol_name;
    (void)p1; (void)p2;

    return (s.value & 0xFF)
         ^ (d & 0xFF)
         ^ (int)(g_login_template.magic & 0xFFu)
         ^ (int)(g_login_template.sid & 0xFFu);
}
