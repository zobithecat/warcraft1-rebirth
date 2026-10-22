"""Worms (WRMS.EXE) settings for recomp/tools/lift.py (--profile)."""

# Watcom's int386x core: it pushes the address of an `int N; ret` stub
# (0x47EA8 + 3*N) and "returns" into it, which lifted code cannot follow.
HLE = {0x47E02: "int386 dispatch"}

WRAP = {}

# The sound mixer's inner loops (0x38DBF, 0x39C04) and a few blitters patch
# their own displacements and immediates (placeholder 0x7FFFFFFF on disk).
PATCH_OPERANDS = True

# Ballistics and the C runtime use the x87.
FPU = True
