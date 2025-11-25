#include <stdlib.h>
#include <string.h>
#include "packet.h"
#include "crypto_stream_xsalsa20.h"
#include "crypto_onetimeauth_poly1305.h"

#if crypto_stream_xsalsa20_KEYBYTES != packet_KEYBYTES
#error "crypto_stream_xsalsa20_KEYBYTES != packet_KEYBYTES"
#endif

#if crypto_stream_xsalsa20_NONCEBYTES != packet_NONCEBYTES
#error "crypto_stream_xsalsa20_NONCEBYTES != packet_NONCEBYTES"
#endif

static unsigned char packet[packet_MAXBYTES];
/* 16 bytes of zeros (not transmitted) */
/* 16-byte authenticator for encrypted data */
/* encrypted data */
/* unencrypted data */

static int packetformat; /* 0: invalid; 1: plaintext; 2: ciphertext+context */
static long long packetpos = 32; /* end of data; always between 32 and packet_MAXBYTES */

static void invalid(void)
{
  packetformat = 0;
  packetpos = 32;
}

void packet_clear(void)
{
  memset(packet+16,0,16);
  packetpos = 32;
  packetformat = 1;
}

void packet_append(const unsigned char *data,long long datalen)
{
  if ((datalen < 0) || (datalen > packet_MAXBYTES-packetpos)) invalid();
  if (!packetformat) return;
  memcpy(packet+packetpos,data,datalen);
  packetpos += datalen;
}

/* encrypt and authenticate packet in place using key k */
void packet_encrypt(const unsigned char *n,const unsigned char *k)
{
  if (packetformat != 1) invalid();
  if (!packetformat) return;
  packetformat = 2;
  crypto_stream_xsalsa20_xor(packet,packet,packetpos,n,k);
  crypto_onetimeauth_poly1305(packet+16,packet+32,packetpos-32,packet);
  memset(packet,0,16);
}

void packet_outgoing(unsigned char *data,long long datalen)
{
  if ((packetformat == 2) && (datalen == packetpos-16)) {
    packetpos = 16;
    memcpy(data,packet+16,datalen);
  } else {
    memset(data,0,datalen);
    invalid();
  }
}

void packet_incoming(const unsigned char *data,long long datalen)
{
  memset(packet+16,0,16);
  if (datalen < 16) {
    invalid();
  } else {
    packetformat = 2;
    packetpos = 16;
    packet_append(data,datalen);
  }
}

int packet_decrypt(const unsigned char *n,const unsigned char *k)
{
  unsigned char subkey[32];
  if (packetformat != 2) invalid();
  if (!packetformat) return -1;
  packetformat = 1;
  crypto_stream_xsalsa20(subkey,32,n,k);
  if (crypto_onetimeauth_poly1305_verify(packet+16,packet+32,packetpos-32,subkey) != 0) {
    invalid();
    return -1;
  }
  crypto_stream_xsalsa20_xor(packet,packet,packetpos,n,k);
  memset(packet,0,32);
  return 0;
}

void packet_extract(unsigned char *data,long long datalen)
{
  if ((datalen < 0) || (datalen > packetpos-32)) invalid();
  if (!packetformat) {
    memset(data,0,datalen);
    return;
  }
  packetpos -= datalen;
  memcpy(data,packet+packetpos,datalen);
}

int packet_isok(void)
{
  if (packetformat != 1) return 0;
  if (packetpos != 32) return 0;
  return 1;
}
