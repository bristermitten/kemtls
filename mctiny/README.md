Prerequisites:

* Intel/AMD CPU with AVX2 (Haswell or newer).

* Linux.

* 1GB free disk space.

* Standard compilation environment
  (e.g., `apt install build-essential` on Debian/Ubuntu).

* Python 3 (e.g., `apt install python3` on Debian/Ubuntu).

* `xsltproc` for `libkeccak` (e.g., `apt install xsltproc` on Debian/Ubuntu).

* If you want to run `make documentation` to convert these `*.md` files
  into `*.html`: `pandoc` (e.g., `apt install pandoc` on Debian/Ubuntu).

Compile (this downloads and extracts crypto pieces from the SUPERCOP
benchmarking framework, and takes a few minutes for crypto self-tests):

       make

Create the server's secret key and public key:

       ./mctiny-master state

Run the server:

       ./mctiny-server state 127.0.0.1 12345 &

Run the client using the server's public key:

       ./mctiny-client state/public/* 127.0.0.1 12345

The client prints some performance information, finishes the connection,
and terminates. The server continues running to handle any number of
clients. As a sanity check, the client and the server each print two
bytes of the session key.

To run the client on another machine, copy the `state/public/*` file to
the other machine, and replace both occurrences of `127.0.0.1` with the
server's name or IP address.

To rotate the server cookie keys once:

       ./mctiny-rotate state

Rotation keeps the last 8 keys. If, e.g., `mctiny-rotate` is run every
minute then each cookie expires between 7 and 8 minutes after being
generated.

### Internal documentation

[`hash` library](hash.html)

[`packet` library](packet.html)

[`pacing` library](pacing.html)

[`mctiny` library](mctiny.html)
