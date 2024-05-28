# zonec
Zone parser used from NSD 1.4 to NSD 4.9, isolated for benchmarking. The
parser is modified to write to a pre-allocated RDATA buffer instead of
individually allocated fields for each item so actual parsing performance
can be measured.

Some quick measurements show simdzone is more than 10x faster.

NSD:
```
time ./zonec-test se. ../../zones/se.zone
Parsed 8924051 records

real    0m17.074s
user    0m16.927s
sys     0m0.129s
```

simdzone:
```
time ./zone-bench parse ../../zones/se.zone
Selected target haswell
Parsed 8924051 records

real    0m1.360s
user    0m1.216s
sys     0m0.142s
```

**THIS WILL NOT BE A MAINTAINED PROJECT, USE simdzone!!**
