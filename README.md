# zonec
Zone parser used from NSD 1.4 to NSD 4.9, isolated for benchmarking. The
parser is modified to write to a pre-allocated RDATA buffer instead of
individually allocated fields for each item so actual parsing performance
can be measured.

**THIS WILL NOT BE A MAINTAINED PROJECT, USE simdzone!!**
