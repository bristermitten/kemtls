#include <sys/time.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include "randombytes.h"
#include "hash.h"
#include "packet.h"
#include "mctiny.h"
#include "pacing.h"

#define SCHEDULING_TOLERANCE 0.001

int randomly_destroy; /* destroy this many packets out of each 32 */

int s;

long long packetssent;
long long packetsreceived;
long long bytessent;
long long bytesreceived;

void note(const char *what,const unsigned char *data,long long datalen)
{
  struct timeval tv;
  unsigned int x0,x21,x22,x23;

  if (datalen >= 24) {
    x0 = data[datalen-24];
    x21 = data[datalen-3];
    x22 = data[datalen-2];
    x23 = data[datalen-1];
  } else {
    x0 = x21 = x22 = x23 = 0;
  }

  gettimeofday(&tv,0);
  fprintf(stderr,"%s %ld.%06ld %lld %02x...%02x%02x%02x\n"
    ,what,tv.tv_sec,tv.tv_usec,datalen
    ,x0,x21,x22,x23);
}

void mysend(const unsigned char *data,long long datalen)
{
  packetssent += 1;
  bytessent += datalen;
  note(">",data,datalen);
  if (randomly_destroy) if ((random()&31) < randomly_destroy) return;
  send(s,data,datalen,0);
}

const char progname[] = "mctiny-client";

void die_usage(void)
{
  fprintf(stderr,"%s: usage: %s serverpkfile serveraddr serverport\n",progname,progname);
  exit(100);
}

unsigned char kmaster[mctiny_SESSIONKEYBYTES];
unsigned char nonce[packet_NONCEBYTES];

unsigned char pk[mctiny_PUBLICKEYBYTES];
unsigned char clientsk[mctiny_SECRETKEYBYTES];

unsigned char serverpkhash[32];

unsigned char ciphertext[mctiny_CIPHERTEXTBYTES];

unsigned char udp[packet_MAXBYTES];
long long udplen;

struct pacing_connection pacingc;
struct pacing_packet pacing0;
struct pacing_packet pacing1[mctiny_ROWBLOCKS][mctiny_COLBLOCKS];
struct pacing_packet pacing2[mctiny_PIECES];
struct pacing_packet pacing3;

unsigned char query0[mctiny_QUERY0BYTES];
int flagcookie0;
unsigned char cookie0[mctiny_COOKIE0BYTES]; /* initialized if flagcookie0 */
unsigned char longtermnonce[packet_NONCEBYTES]; /* initialized if flagcookie0 */

const unsigned char blankcookie1[mctiny_COOKIEBLOCKBYTES];
int flagcookie1[mctiny_ROWBLOCKS][mctiny_COLBLOCKS];
unsigned char cookie1[mctiny_ROWBLOCKS][mctiny_COLBLOCKS][mctiny_COOKIEBLOCKBYTES];

int flagsynd2[mctiny_PIECES];
unsigned char synd2[mctiny_PIECES][mctiny_PIECEBYTES];

unsigned char synd3[mctiny_COLBYTES];

int flagcookie9;
unsigned char cookie9[mctiny_COOKIE9BYTES];

unsigned char ksession[mctiny_SESSIONKEYBYTES];

unsigned char block[mctiny_BLOCKBYTES];

unsigned char extensions[512];

int query0_isready(void)
{
  return !flagcookie0;
}

void query0_prepare(void)
{
  randombytes(nonce,sizeof nonce);
  nonce[sizeof nonce-2] = 0;
  nonce[sizeof nonce-1] = 0;

  packet_clear();
  packet_append(extensions,sizeof extensions);
  packet_encrypt(nonce,kmaster);
  packet_append(serverpkhash,sizeof serverpkhash);
  packet_append(ciphertext,sizeof ciphertext);
  packet_append(nonce,sizeof nonce);
  packet_outgoing(query0,sizeof query0);
}

void query0_do(void)
{
  mysend(query0,sizeof query0);
  pacing_transmitted(&pacingc,&pacing0);
}

int query1_isready(long long rowpos,long long colpos)
{
  if (rowpos < 0) return 0; /* internal bug */
  if (rowpos >= mctiny_ROWBLOCKS) return 0; /* internal bug */
  if (colpos < 0) return 0; /* internal bug */
  if (colpos >= mctiny_COLBLOCKS) return 0; /* internal bug */
  if (flagcookie1[rowpos][colpos]) return 0;
  if (!flagcookie0) return 0;
  return 1;
}

void query1(long long rowpos,long long colpos)
{
  if (!query1_isready(rowpos,colpos)) return;

  mctiny_pk2block(block,pk,rowpos,colpos);

  /* rowpos is "i-1" in spec */
  /* colpos is "j-1" in spec */
  memcpy(nonce,longtermnonce,sizeof nonce);
  nonce[sizeof nonce-2] = rowpos*2;
  nonce[sizeof nonce-1] = 64+colpos;

  packet_clear();
  packet_append(block,sizeof block);
  packet_encrypt(nonce,kmaster);
  packet_append(cookie0,sizeof cookie0);
  packet_append(nonce,sizeof nonce);
  packet_outgoing(udp,mctiny_QUERY1BYTES);
  mysend(udp,mctiny_QUERY1BYTES);
  pacing_transmitted(&pacingc,&pacing1[rowpos][colpos]);
}

int query2_isready(long long piecepos)
{
  long long rowpos,colpos;

  if (flagsynd2[piecepos]) return 0;

  for (rowpos = piecepos*mctiny_V;rowpos < (piecepos+1)*mctiny_V;++rowpos)
    if (rowpos >= 0 && rowpos < mctiny_ROWBLOCKS)
      for (colpos = 0;colpos < mctiny_COLBLOCKS;++colpos)
        if (!flagcookie1[rowpos][colpos]) return 0;

  return 1;
}

void query2(long long piecepos)
{
  long long rowpos,colpos;

  if (!query2_isready(piecepos)) return;

  memcpy(nonce,longtermnonce,sizeof nonce);
  nonce[sizeof nonce-2] = piecepos*2;
  nonce[sizeof nonce-1] = 64+32;

  packet_clear();
  for (rowpos = piecepos*mctiny_V;rowpos < (piecepos+1)*mctiny_V;++rowpos)
    for (colpos = 0;colpos < mctiny_COLBLOCKS;++colpos)
      if (rowpos >= 0 && rowpos < mctiny_ROWBLOCKS)
        packet_append(cookie1[rowpos][colpos],sizeof cookie1[rowpos][colpos]);
      else
        packet_append(blankcookie1,sizeof blankcookie1); /* XXX: could compress */
  packet_encrypt(nonce,kmaster);
  packet_append(cookie0,sizeof cookie0);
  packet_append(nonce,sizeof nonce);
  packet_outgoing(udp,mctiny_QUERY2BYTES);
  mysend(udp,mctiny_QUERY2BYTES);
  pacing_transmitted(&pacingc,&pacing2[piecepos]);
}

int query3_isready(void)
{
  long long piecepos;

  if (flagcookie9) return 0;
  for (piecepos = 0;piecepos < mctiny_PIECES;++piecepos)
    if (!flagsynd2[piecepos]) return 0;
  return 1;
}

void query3(void)
{
  if (!query3_isready()) return;

  memcpy(nonce,longtermnonce,sizeof nonce);
  nonce[sizeof nonce-2] = 254;
  nonce[sizeof nonce-1] = 255;

  mctiny_mergepieces(synd3,synd2);

  packet_clear();
  packet_append(synd3,sizeof synd3);
  packet_encrypt(nonce,kmaster);
  packet_append(cookie0,sizeof cookie0);
  packet_append(nonce,sizeof nonce);
  packet_outgoing(udp,mctiny_QUERY3BYTES);
  mysend(udp,mctiny_QUERY3BYTES);
  pacing_transmitted(&pacingc,&pacing3);
}

void client_recv(void)
{
  unsigned int nonce0,nonce1;

  for (;;) {
    udplen = recv(s,udp,sizeof udp,MSG_DONTWAIT); /* XXX: do portable non-blocking */
    if (udplen < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return;
      continue;
    }
    if (udplen > sizeof udp) continue;

    if (randomly_destroy) if ((random()&31) < randomly_destroy) continue;

    ++packetsreceived;
    bytesreceived += udplen;
    note("<",udp,udplen);
  
    packet_incoming(udp,udplen);
    packet_extract(nonce,sizeof nonce);
    if (packet_decrypt(nonce,kmaster) != 0) continue;

    nonce0 = nonce[sizeof nonce-2];
    nonce1 = nonce[sizeof nonce-1];

    if (!(nonce0&1)) continue;
  
    if (!(nonce1&64)) {
      if (nonce0 != 1) continue;
      if (nonce1) continue;
      if (udplen != mctiny_REPLY0BYTES) continue;
      if (flagcookie0) continue;

      packet_extract(cookie0,sizeof cookie0);
      if (!packet_isok()) continue; /* internal bug */

      pacing_acknowledged(&pacingc,&pacing0);
  
      fprintf(stderr,"cookie0\n");
      flagcookie0 = 1;

      memcpy(longtermnonce,nonce,sizeof nonce);
    } else if (!(nonce1&32)) {
      long long rowpos = 127&(nonce0/2);
      long long colpos = 31&nonce1;
      if (rowpos < 0) continue; /* impossible */
      if (colpos < 0) continue; /* impossible */
      if (rowpos >= mctiny_ROWBLOCKS) continue;
      if (colpos >= mctiny_COLBLOCKS) continue;
      if (nonce0 != 2*rowpos+1) return;
      if (nonce1 != 64+colpos) return;
      if (udplen != mctiny_REPLY1BYTES) continue;
      if (flagcookie1[rowpos][colpos]) continue;
  
      packet_extract(cookie1[rowpos][colpos],sizeof cookie1[rowpos][colpos]);
      packet_extract(cookie0,sizeof cookie0);
      if (!packet_isok()) continue; /* internal bug */

      pacing_acknowledged(&pacingc,&pacing1[rowpos][colpos]);
      flagcookie1[rowpos][colpos] = 1;
    } else if (!(nonce1&16)) {
      long long piecepos = 127&(nonce0/2);
      if (piecepos < 0) continue; /* impossible */
      if (piecepos >= mctiny_PIECES) continue;
      if (nonce0 != 2*piecepos+1) continue;
      if (nonce1 != 64+32) continue;
      if (udplen != mctiny_REPLY2BYTES) continue;
      if (flagsynd2[piecepos]) continue;

      packet_extract(synd2[piecepos],mctiny_PIECEBYTES);
      packet_extract(cookie0,sizeof cookie0);
      if (!packet_isok()) continue; /* internal bug */

      pacing_acknowledged(&pacingc,&pacing2[piecepos]);
      flagsynd2[piecepos] = 1;
    } else {
      if (nonce0 != 255) return;
      if (nonce1 != 255) return;
      if (udplen != mctiny_REPLY3BYTES) continue;
      if (flagcookie9) continue;

      packet_extract(ciphertext,sizeof ciphertext);
      packet_extract(cookie9,sizeof cookie9);
      if (!packet_isok()) continue; /* internal bug */

      pacing_acknowledged(&pacingc,&pacing3);
      flagcookie9 = 1;
    }
  }
}

double trytransmitting(void)
{
  long long piecepos,rowpos,colpos;
  double when = 240;
  double when2;

  if (query0_isready()) {
    when2 = pacing_whenrto(&pacingc,&pacing0);
    if (when2 <= SCHEDULING_TOLERANCE) {
      query0_do();
      return 0;
    }
    if (when2 < when) when = when2;
  }

  for (rowpos = 0;rowpos < mctiny_ROWBLOCKS;++rowpos)
    for (colpos = 0;colpos < mctiny_COLBLOCKS;++colpos)
      if (query1_isready(rowpos,colpos)) {
        when2 = pacing_whenrto(&pacingc,&pacing1[rowpos][colpos]);
        if (when2 <= SCHEDULING_TOLERANCE) {
          query1(rowpos,colpos);
          return 0;
        }
        if (when2 < when) when = when2;
      }

  for (piecepos = 0;piecepos < mctiny_PIECES;++piecepos)
    if (query2_isready(piecepos)) {
      when2 = pacing_whenrto(&pacingc,&pacing2[piecepos]);
      if (when2 <= SCHEDULING_TOLERANCE) {
        query2(piecepos);
        return 0;
      }
      if (when2 < when) when = when2;
    }

  if (query3_isready()) {
    when2 = pacing_whenrto(&pacingc,&pacing3);
    if (when2 <= SCHEDULING_TOLERANCE) {
      query3();
      return 0;
    }
    if (when2 < when) when = when2;
  }

  return when;
}

#define PACKETOVERHEAD 66 /* presumed number of extra bytes on network for each packet */

void client(void)
{
  long long piecepos,rowpos,colpos;

  pacing_connection_init(&pacingc);

  pacing_packet_init(&pacing0,mctiny_QUERY0BYTES+PACKETOVERHEAD);
  for (rowpos = 0;rowpos < mctiny_ROWBLOCKS;++rowpos)
    for (colpos = 0;colpos < mctiny_COLBLOCKS;++colpos)
      pacing_packet_init(&pacing1[rowpos][colpos],mctiny_QUERY1BYTES+PACKETOVERHEAD);
  for (piecepos = 0;piecepos < mctiny_PIECES;++piecepos)
    pacing_packet_init(&pacing2[piecepos],mctiny_QUERY2BYTES+PACKETOVERHEAD);
  pacing_packet_init(&pacing3,mctiny_QUERY3BYTES+PACKETOVERHEAD);

  hash(serverpkhash,pk,sizeof pk);

  if (mctiny_enc(ciphertext,kmaster,pk) != 0) {
    fprintf(stderr,"%s: fatal: internal error: enc failed\n",progname);
    exit(111);
  }

  /* ----- above: pk is serverpk; below: pk is clientpk */

  if (mctiny_keypair(pk,clientsk) != 0) {
    fprintf(stderr,"%s: fatal: internal error: keygen failed\n",progname);
    exit(111);
  }

  query0_prepare();

  while (!flagcookie9) {
    double when;
    struct pollfd p[1];
    p[0].fd = s;
    p[0].events = POLLIN;

    /* XXX: avoid busy-looping on ECONNREFUSED etc.; maybe skip connect()? */

    pacing_now_update(&pacingc);

    for (;;) {
      when = pacing_whendecongested(&pacingc,1200+PACKETOVERHEAD);
      if (when > SCHEDULING_TOLERANCE) break;
      when = trytransmitting();
      if (when > SCHEDULING_TOLERANCE) break;
    }

    if (poll(p,1,1000*when) == 1) {
      pacing_now_update(&pacingc);
      client_recv();
    }
  }

  mctiny_dec(ksession,ciphertext,clientsk); /* cannot fail */
  fprintf(stderr,"client ksession %02x...%02x\n",ksession[0],ksession[31]);
  fprintf(stderr,"client packets sent %lld received %lld\n",packetssent,packetsreceived);
  fprintf(stderr,"client bytes sent %lld received %lld\n",bytessent,bytesreceived);
}

char printip[NI_MAXHOST];
char printport[NI_MAXSERV];

int main(int argc,char **argv)
{
  const char *serverpkfile = 0;
  const char *serveraddr = 0;
  const char *serverport = 0;
  struct addrinfo hints;
  struct addrinfo *addrhead;
  struct addrinfo *addr;
  int connected;
  int r;
  FILE *fi;

  if (getenv("RANDOMLY_DESTROY")) randomly_destroy = 1;
  srandom(getpid());

  if (!*argv++) die_usage();
  serverpkfile = *argv;
  if (!*argv++) die_usage();
  serveraddr = *argv;
  if (!*argv++) die_usage();
  serverport = *argv;
  if (!*argv++) die_usage();

  fi = fopen(serverpkfile,"r");
  if (!fi) {
    fprintf(stderr,"%s: fatal: unable to read %s: %s\n",progname,serverpkfile,strerror(errno));
    exit(111);
  }
  errno = EPROTO;
  if (fread(pk,sizeof pk,1,fi) < 1) {
    fprintf(stderr,"%s: fatal: unable to read %s: %s\n",progname,serverpkfile,strerror(errno));
    exit(111);
  }
  fclose(fi);

  memset(&hints,0,sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  r = getaddrinfo(serveraddr,serverport,&hints,&addrhead);
  if (r != 0) {
    fprintf(stderr,"%s: fatal: getaddrinfo %s %s failed: %s\n",progname,serveraddr,serverport,gai_strerror(r));
    exit(111);
  }

  connected = 0;
  for (addr = addrhead;addr;addr = addr->ai_next) {
    /* XXX: should have outgoing packets cycle through addresses */
    s = socket(addr->ai_family,addr->ai_socktype,addr->ai_protocol);
    if (s == -1) {
      fprintf(stderr,"%s: warning: socket %d,%d,%d failed: %s\n"
        ,progname
        ,addr->ai_family,addr->ai_socktype,addr->ai_protocol
        ,strerror(errno));
      continue;
    }
    if (connect(s,addr->ai_addr,addr->ai_addrlen) == -1) {
      const char *bindfailure = strerror(errno);
      r = getnameinfo(addr->ai_addr,addr->ai_addrlen,printip,sizeof printip,printport,sizeof printport,NI_NUMERICHOST | NI_NUMERICSERV);
      if (r == 0) {
        fprintf(stderr,"%s: warning: connect %d,%d,%d %s %s failed: %s\n"
          ,progname
          ,addr->ai_family,addr->ai_socktype,addr->ai_protocol
          ,printip,printport
          ,bindfailure);
      } else {
        fprintf(stderr,"%s: warning: connect %d,%d,%d failed: %s\n"
          ,progname
          ,addr->ai_family,addr->ai_socktype,addr->ai_protocol
          ,bindfailure);
        fprintf(stderr,"%s: warning: getnameinfo failed: %s\n",progname,gai_strerror(r));
      }
      continue;
    }
    connected = 1;
    break;
  }

  freeaddrinfo(addrhead);

  if (!connected) {
    fprintf(stderr,"%s: fatal: unable to connect to any address\n",progname);
    exit(111);
  }

  if (connected)
    client();

  return 0;
}
