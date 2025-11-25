The `packet` library
generates and parses packets in authenticator-ciphertext-context format.
The library is designed to work in tiny embedded environments
without dynamic memory allocation.
It handles **one packet at a time** in an internal buffer,
and is **not thread-safe**.

A packet in authenticator-ciphertext-context format
has a 16-byte authenticator,
followed by an application-specified number of bytes of ciphertext,
followed by an application-specified number of bytes of context.
The library allows packets as large as `packet_MAXBYTES` bytes;
`packet_MAXBYTES` is 1252.

To generate a packet:

        #include "packet.h"

        unsigned char data1[...];
        unsigned char data2[...];

        unsigned char nonce[packet_NONCEBYTES];
        unsigned char key[packet_KEYBYTES];

        unsigned char data3[...];
        unsigned char data4[...];

        unsigned char outgoing[16
          + sizeof data1 + sizeof data2
          + sizeof data3 + sizeof data4];

        packet_clear();
        packet_append(data1,sizeof data1);
        packet_append(data2,sizeof data2);
        packet_encrypt(nonce,key);
        packet_append(data3,sizeof data3);
        packet_append(data4,sizeof data4);
        packet_outgoing(outgoing,sizeof outgoing);

In this example,
the contents of `data1` and `data2`
are concatenated to form an internal plaintext.
This plaintext is then encrypted and authenticated
to form the ciphertext and authenticator.
The contents of `data3` and `data4`
are concatenated to form the context.

You must follow the pattern of `packet_clear`,
then some number of `packet_append`,
then `packet_encrypt`,
then some number of `packet_append`,
then `packet_outgoing`.
You must fit within the `packet_MAXBYTES` limit.

To parse a packet:

        #include "packet.h"

        unsigned char data1[...];
        unsigned char data2[...];

        unsigned char nonce[packet_NONCEBYTES];
        unsigned char key[packet_KEYBYTES];

        unsigned char data3[...];
        unsigned char data4[...];

        unsigned char incoming[16
          + sizeof data1 + sizeof data2
          + sizeof data3 + sizeof data4];

        packet_incoming(incoming,sizeof incoming);
        packet_extract(data4,sizeof data4);
        packet_extract(data3,sizeof data3);
        if (packet_decrypt(nonce,key) != 0) goto discardpacket;
        packet_extract(data2,sizeof data2);
        packet_extract(data1,sizeof data1);
        if (!packet_isok()) goto discardpacket;

Parsing is like generation but in the opposite order. 
You must follow the pattern of `packet_incoming`,
then some number of `packet_extract`,
then `packet_decrypt`,
then some number of `packet_extract`,
then `packet_isok`.
You must check the return values from `packet_decrypt` and `packet_isok`.

If an incoming packet is too short for `packet_extract`
then `packet_extract` clears its outgoing buffer,
arranges for any subsequent `packet_extract` to do the same,
arranges for any subsequent `packet_decrypt` to return nonzero,
and arranges for any subsequent `packet_isok` to return zero.

### Security warnings

Keys must be kept secret.

You must not reuse a nonce to create two different ciphertexts
under the same key.

`packet_decrypt` checks that the ciphertext
has been authenticated under this nonce.
It does not check the context
(unless this is implicit from,
e.g., the nonce being a copy of the context).
