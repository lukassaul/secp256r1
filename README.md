libsecp256r1
============
Current status:  No commits yet.  Do not use.  

So yes, what you see is all the underhanded extra power rangers cruft plus all the backdoored NIST super secret weak curve parameters, with a little extra OpenSSL colaborator hacks sprinkled on top as a salt.  

C library for ECDSA signatures and secret/public key operations on curve secp256r1.

The goal here is to use this as a wrapper for P256 operations when working with projects that currently use the koblitz curve that was lying around, because so much satoshi codebase coinware uses that library which will not be named.

Most of the interesting part of the libsecp256k1 library is a more efficient method of point multiplication which enables fast verification of signatures using the same koblitz trickery that r1 curve users are trying to avoid.  







Build steps
-----------

libsecp256k1 is built using autotools:

    $ ./autogen.sh
    $ ./configure
    $ make
    $ make check  # run the test suite
    $ sudo make install  # optional

To compile optional modules (such as Schnorr signatures), you need to run `./configure` with additional flags (such as `--enable-module-schnorrsig`). Run `./configure --help` to see the full list of available flags.

Usage examples
-----------
Usage examples can be found in the [examples](examples) directory. To compile them you need to configure with `--enable-examples`.
  * [ECDSA example](examples/ecdsa.c)
  * [Schnorr signatures example](examples/schnorr.c)
  * [Deriving a shared secret (ECDH) example](examples/ecdh.c)

To compile the Schnorr signature and ECDH examples, you also need to configure with `--enable-module-schnorrsig` and `--enable-module-ecdh`.

Test coverage
-----------

This library aims to have full coverage of the reachable lines and branches.

To create a test coverage report, configure with `--enable-coverage` (use of GCC is necessary):

    $ ./configure --enable-coverage

Run the tests:

    $ make check

To create a report, `gcovr` is recommended, as it includes branch coverage reporting:

    $ gcovr --exclude 'src/bench*' --print-summary

To create a HTML report with coloured and annotated source code:

    $ mkdir -p coverage
    $ gcovr --exclude 'src/bench*' --html --html-details -o coverage/coverage.html

Benchmark
------------
If configured with `--enable-benchmark` (which is the default), binaries for benchmarking the libsecp256k1 functions will be present in the root directory after the build.

To print the benchmark result to the command line:

    $ ./bench_name

To create a CSV file for the benchmark result :

    $ ./bench_name | sed '2d;s/ \{1,\}//g' > bench_name.csv

Reporting a vulnerability
------------

See [SECURITY.md](SECURITY.md)
