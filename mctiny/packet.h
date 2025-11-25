/* See packet.md for documentation. */

#ifndef packet_h
#define packet_h

#define packet_KEYBYTES 32
#define packet_NONCEBYTES 24
#define packet_MAXBYTES 1252

extern void packet_clear(void);
extern void packet_append(const unsigned char *,long long);
extern void packet_encrypt(const unsigned char *,const unsigned char *);
extern void packet_outgoing(unsigned char *,long long);

extern void packet_incoming(const unsigned char *,long long);
extern int packet_decrypt(const unsigned char *,const unsigned char *);
extern void packet_extract(unsigned char *,long long);
extern int packet_isok(void);

#endif
