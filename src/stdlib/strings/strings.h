#pragma once

// A constant whose low-order bits are all 1 and is greater than the maximum
// index number. To resolve the verifier's complaint that the off range is too
// large, resulting in "possible" access beyond the range of ARRAY[], we use a
// constant value to constrain `index` to help the verifier.
#define ERROR_INDEX_MASK 0xff
#define SIGNAL_INDEX_MASK 0xff
#define SYSCALL_INDEX_MASK 0x3ff
