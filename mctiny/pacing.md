A connection sends data as a series of packets. The `pacing` library
answers the question "When should I transmit this packet?" The library
is specifically designed to be usable inside protocols that provide
reliable connections on top of UDP.

### Data structures

The `pacing` library does not dynamically allocate memory. You are
responsible for setting aside storage for the structures described here.

You need a `struct pacing_connection` to track the global state of the
connection (e.g., an estimate of the round-trip time). To initialize a
`struct pacing_connection`:

        #include "pacing.h"

        struct pacing_connection c;

        pacing_newconnection(&c);

You also need many `struct pacing_packet`. "Many" means the number of
packets that you're willing to prepare and send without having received
acknowledgments yet. Each `struct pacing_packet` tracks the state of one
packet (e.g., when the packet was last transmitted). You can deallocate
this structure once the packet has been acknowledged as being
successfully received. Currently `struct pacing_packet` is 64 bytes. To
initialize a `struct pacing_packet`:

        #include "pacing.h"

        struct pacing_packet p;
        long long len;

        pacing_packet_init(&p,len);

Here `len` is an estimate for the number of bytes that the packet will
occupy on the network.

### Recording packet transmissions and acknowledgments

Call `pacing_transmitted` whenever you send a packet through a
connection:

        #include "pacing.h"

        struct pacing_connection c;
        struct pacing_packet p;

        pacing_transmitted(&c,&p);

Call `pacing_acknowledged` when you learn that the packet has been
received successfully:

        #include "pacing.h"

        struct pacing_connection c;
        struct pacing_packet p;

        pacing_acknowledged(&c,&p);

If you don't learn that a packet is received successfully, you will end
up re-sending it later for reliability, perhaps several times. Make sure
to call `pacing_transmitted` for each transmission.

Internally, one of the goals of `pacing_acknowledged` is to figure out
the connection's round-trip time. For packets that are retransmitted, it
is generally not clear which transmission is being acknowledged. The
`pacing` library automatically uses "Karn's algorithm", meaning that it
skips retransmitted packets in calculating round-trip times.

In some protocols, multiple transmissions of a packet are distinguished
on the network (with, e.g., a counter or sending timestamp), and this
distinction is reflected in acknowledgments, removing the ambiguity
handled by Karn's algorithm. Currently the `pacing` library does not
provide a way to receive this information from the protocol.

### Recording timestamps

Before calling `pacing_transmitted` or `pacing_acknowledged`, call
`pacing_now_update` to record the current time:

        #include "pacing.h"

        struct pacing_connection c;

        pacing_now_update(&c);

You could call `pacing_now_update` before _every_ call to
`pacing_transmitted` or `pacing_acknowledged`, but this is not required
and is generally not desirable. Normally the `pacing` library is called
from an event loop that

* waits for incoming packets or the next time to send outgoing packets,
* handles all available incoming packets (perhaps calling
  `pacing_acknowledged` one or more times), and
* handles all outgoing packets that are ready to be sent (perhaps
  calling `pacing_transmitted` one or more times.

You should call `pacing_now_update` after the waiting step.

### Deciding when a packet is ready to send

For efficiency, one wants to send packets as quickly as possible.
However, if the connection is **congested**, meaning that packets have
piled up in an intermediate buffer, then it is better to wait until the
connection is decongested. Furthermore, if a particular packet has
already been sent then one should wait until its **retransmittion
timeout** before sending that packet again.

To see whether the connection is sufficiently decongested to send a packet:

        #include "pacing.h"

        const struct pacing_connection c;
        long long len;
        double when;

        when = pacing_whendecongested(&c,len);

Here `len` is an estimate for the number of bytes that the next packet
will occupy on the network. The timing does not depend much on this
number, so don't worry about getting the estimate exactly right.

If `when<=0` then the connection is sufficiently decongested to send a
packet now. If `when>0` then you should wait `when` seconds and check
`pacing_whendecongested` again. If you are using a scheduling mechanism
with low precision then you may wish to set a cutoff slightly different
from 0: e.g., if you are using a `poll` event loop then you should treat
`when<0.001` as sufficiently decongested.

The time measured by `when` is after the most recent call to
`pacing_now_update`.

To see whether a particular packet is ready to send, either because it
has not been sent before or because it has reached its retransmission
timeout:

        const struct pacing_connection c;
        const struct pacing_packet p;
        double when;

        when = pacing_whenrto(&c,&p);

The `pacing_whenrto` calculation does not include the
`pacing_whendecongested` calculation: you should not send a packet
unless both calculations indicate `when<=0`.

### Internals

`struct pacing_packet` and `struct pacing_connection` are defined in
`pacing.h` as arrays of doubles, currently sizes 8 and 128 respectively.
The `pacing` library reinterprets these internally as meaningful
structures, namely `struct packet` and `struct connection`. Changes to
these structures do not require recompilation of callers as long as the
new structures continue to fit into 64 and 1024 bytes respectively.

Another common way to support changes in library data structures is for
callers to ask the library for a pointer to a newly allocated structure.
A more space-efficient approach is for the library to simply provide a
constant integer specifying the number of bytes in the structure; the
caller can then allocate an array of structures. However, the `pacing`
library is designed to be usable in programs that perform no dynamic
memory allocation; static allocation also simplifies the calling code.

Currently `pacing` uses `CLOCK_MONOTONIC`, which typically counts
seconds since boot, not counting time that a laptop is suspended.

Currently `pacing` converts `CLOCK_MONOTONIC` timestamps to `double` for
internal calculations. If a system stays up for hundreds of years then
the gap between adjacent timestamps will grow to the scale of a
microsecond. More precise timing than this could be desirable to spread
out packets on an extremely fast network. The API is designed so that
`pacing` can switch to more precise internal timestamps without any
recompilation of callers.

Currently `pacing` implements _some_ standard TCP ideas including _part_
of the BBR v1 congestion-control algorithm:

* BBR estimation of target bandwidth ("delivery rate").
* BBR estimation of target round-trip time ("rtprop").
* BBR control loop to probe bandwidth and RTT.
* Packet pacing; required for BBR, and a good idea anyway.
* Standard retransmission-timeout estimation.

However, this has not been audited and could have serious bugs.
Furthermore, some standard ideas and some BBR ideas are not fully
implemented: e.g., negative acknowledgments don't trigger retransmit
until RTO. Furthermore, BBR doesn't make any serious effort to estimate
the number of competing flows on the same bottleneck link.
