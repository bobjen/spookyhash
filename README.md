SpookyHash is a fast and thorough 128-bit noncryptographic hash function I first published in 2012. 20.6GB/sec for 16384 byte keys.

Documentation: https://burtleburtle.net/bob/hash/spooky.html .

There is a Rust translation in the `rust/` directory. It produces identical hashes to the C++ implementation. Throughput below is from `DoTimingSmall` (10 million iterations, cached, on one machine); C++ compiled with `g++ -O3`, Rust with `cargo build --release`.

| bytes | C++ GB/s | Rust GB/s |
|------:|---------:|----------:|
|     1 |     0.19 |      0.14 |
|     2 |     0.38 |      0.27 |
|     4 |     0.70 |      0.56 |
|     8 |     1.47 |      1.14 |
|    16 |     1.44 |      1.29 |
|    32 |     2.90 |      2.44 |
|    64 |     3.83 |      3.34 |
|   128 |     4.54 |      3.98 |
|   256 |     6.16 |      6.02 |
|   512 |     9.33 |      8.92 |
|  1024 |    12.83 |     12.27 |
|  2048 |    15.85 |     14.89 |
|  4096 |    17.82 |     16.97 |
|  8192 |    18.68 |     18.03 |
| 16384 |    19.54 |     18.62 |
