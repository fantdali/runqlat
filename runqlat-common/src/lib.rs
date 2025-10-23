#![no_std]

/// Max number of slots in histograms.
/// log2(1_000_000) ~= 19.93, so 20 slots for 0..1s in us
pub const MAX_SLOTS: usize = 20;

// Example:
//      usecs               : count     distribution
//          0 -> 1          : 233      |***********                             |
//          2 -> 3          : 742      |************************************    |
//          4 -> 7          : 203      |**********                              |
//          8 -> 15         : 173      |********                                |
//         16 -> 31         : 24       |*                                       |
//         32 -> 63         : 0        |                                        |
//         64 -> 127        : 30       |*                                       |
//        128 -> 255        : 6        |                                        |
//        256 -> 511        : 3        |                                        |
//        512 -> 1023       : 5        |                                        |
//       1024 -> 2047       : 27       |*                                       |
pub type Histogram = [u32; MAX_SLOTS];
