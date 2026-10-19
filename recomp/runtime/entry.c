/* Entry point for running a lifted function from a test harness (ctypes). */
#include "x86.h"

typedef struct { uint32_t addr; void (*fn)(Cpu *); } LiftedEntry;
extern const LiftedEntry lifted_table[];

/* Runs the lifted function at guest address `addr` on `regs` (8 GPRs in x86
 * encoding order, updated in place) and `mem`; writes to [ro_lo, ro_hi) fault.
 * Returns a STOP_* code;
 * -1 if no function was lifted for `addr`. */
int lifted_run(uint32_t addr, uint32_t *regs, uint8_t *mem, uint32_t mem_size,
               uint32_t ro_lo, uint32_t ro_hi, int64_t budget, uint32_t *fault_addr) {
    const LiftedEntry *e = lifted_table;
    while (e->fn && e->addr != addr) e++;
    if (!e->fn) return -1;

    Cpu c;
    memset(&c, 0, sizeof c);        /* flat segments, no hooks */
    memcpy(c.r, regs, sizeof c.r);
    c.mem = mem;
    c.mem_size = mem_size;
    c.budget = budget;
    c.fault_addr = 0;
    c.ro_lo = ro_lo;
    c.ro_hi = ro_hi;
    c.ret_to = 0;
    int why = setjmp(c.stop);
    if (why == 0) {
        uint32_t expect = rd32(&c, regs[ESP]);    /* the harness pushed it */
        e->fn(&c);
        memcpy(regs, c.r, sizeof c.r);
        if (c.ret_to != expect) {
            c.fault_addr = c.ret_to;
            why = STOP_BADRET;
        }
    }
    *fault_addr = c.fault_addr;
    return why;
}

int lifted_count(void) {
    int n = 0;
    while (lifted_table[n].fn) n++;
    return n;
}

uint32_t lifted_addr(int i) { return lifted_table[i].addr; }
