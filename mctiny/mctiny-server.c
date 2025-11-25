#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include "randombytes.h"
#include "crypto_verify_32.h"
#include "cpucycles.h"
#include "packet.h"
#include "hash.h"
#include "mctiny.h"

long long cycles;
long long cyclesselected;

const char progname[] = "mctiny-server";

unsigned char udp[packet_MAXBYTES];
long long udplen;

unsigned char kmaster[mctiny_SESSIONKEYBYTES];
unsigned char nonce[packet_NONCEBYTES];
unsigned char cookienonce[packet_NONCEBYTES];

unsigned char extensions[512];

unsigned char serverpkhash[32];
unsigned char pkhashhex[65];
char fnsk[100];
unsigned char serversk[mctiny_SECRETKEYBYTES];

/* XXX: cache! */
int serversk_from_hash(void)
{
  int ok;
  long long i;
  FILE *fi;

  randombytes(serversk,sizeof serversk);

  for (i = 0;i < 32;++i) {
    int b = serverpkhash[i];
    pkhashhex[2*i] = "0123456789abcdef"[15&(b>>4)];
    pkhashhex[2*i+1] = "0123456789abcdef"[15&b];
  }
  pkhashhex[2*i] = 0;

  if (snprintf(fnsk,sizeof fnsk,"long-term-keys/%s",pkhashhex) >= sizeof fnsk) {
    fprintf(stderr,"%s: alert: internal error: fnsk too small\n",progname);
    return -1;
  }

  ok = 0;
  fi = fopen(fnsk,"r");
  if (fi) {
    errno = EPROTO;
    if (fread(serversk,sizeof serversk,1,fi) == 1) ok = 1;
    fclose(fi);
  }

  if (ok) return 0;
  if (errno == ENOENT) {
    /* silently reject invalid packets */
    return -1;
  }

  fprintf(stderr,"%s: alert: open %s failed: %s\n",progname,fnsk,strerror(errno));
  return -1;
}

unsigned char kcookie_cache[8][33];
time_t kcookie_cache_timestamp[8];
long long kcookie_cache_uses[8];
long long kcookie_cache_latest;

unsigned char kcookie[33];
unsigned char kcookiekmaster[64]; /* could overlap this with kcookie */
unsigned char kcookie_hash[32];

int kcookie_islatest(void)
{
  if (kcookie_cache_latest == (7&(unsigned int) kcookie[32]))
    if (time(0) == kcookie_cache_timestamp[kcookie_cache_latest])
      if (kcookie_cache_uses[kcookie_cache_latest] > 0) {
        --kcookie_cache_uses[kcookie_cache_latest];
        return 1;
      }
  return 0;
}

void kcookie_latest(void)
{
  FILE *fi;
  int ok = 0;

  if (time(0) == kcookie_cache_timestamp[kcookie_cache_latest])
    if (kcookie_cache_uses[kcookie_cache_latest] > 0) {
      --kcookie_cache_uses[kcookie_cache_latest];
      memcpy(kcookie,kcookie_cache[kcookie_cache_latest],sizeof kcookie);
      return;
    }

  fi = fopen("temporary-cookie-keys/latest","r");
  if (fi) {
    if (fread(kcookie,sizeof kcookie,1,fi) == 1) ok = 1;
    fclose(fi);
  }

  if (ok) {
    kcookie_cache_latest = 7&(unsigned int) kcookie[32];
    kcookie_cache_timestamp[kcookie_cache_latest] = time(0);
    kcookie_cache_uses[kcookie_cache_latest] = 10000;
    memcpy(kcookie_cache[kcookie_cache_latest],kcookie,sizeof kcookie);
  } else {
    fprintf(stderr,"%s: alert: unable to read temporary-cookie/keys/latest: %s\n",progname,strerror(errno));
    randombytes(kcookie,sizeof kcookie);
  }
}

char fnkcookie[24] = "temporary-cookie-keys/0";

/* expand kcookie[32] to entire kcookie */
void kcookie_fromid(void)
{
  FILE *fi;
  int kcookieid = 7&(unsigned int) kcookie[32];
  int ok = 0;

  if (time(0) == kcookie_cache_timestamp[kcookieid])
    if (kcookie_cache_uses[kcookieid] > 0) {
      --kcookie_cache_uses[kcookieid];
      memcpy(kcookie,kcookie_cache[kcookieid],sizeof kcookie);
      return;
    }

  fnkcookie[22] = '0'+kcookieid;
  fi = fopen(fnkcookie,"r");
  if (fi) {
    if (fread(kcookie,sizeof kcookie,1,fi) == 1) ok = 1;
    fclose(fi);
  }

  if (ok) {
    kcookie_cache_timestamp[kcookieid] = time(0);
    kcookie_cache_uses[kcookieid] = 10000;
    memcpy(kcookie_cache[kcookieid],kcookie,sizeof kcookie);
  } else {
    randombytes(kcookie,sizeof kcookie);
  }
}

void kcookie_hash_master(void)
{
  memcpy(kcookiekmaster,kcookie,32);
  memcpy(kcookiekmaster+32,kmaster,32);
  hash(kcookie_hash,kcookiekmaster,64);
  /* kcookie_hash is "hash(s_m,S)" in spec */
}

unsigned char clientid[packet_NONCEBYTES-2];
unsigned char cookie0[mctiny_COOKIE0BYTES];
unsigned char cookie1[mctiny_V][mctiny_COLBLOCKS][mctiny_COOKIEBLOCKBYTES];
unsigned char cookie9[mctiny_COOKIE9BYTES];

unsigned char synd1[mctiny_YBYTES];
unsigned char synd2[mctiny_PIECEBYTES];
unsigned char synd3[mctiny_COLBYTES];

unsigned char seed[32];

unsigned char e[mctiny_EBYTES];
unsigned char ciphertext[mctiny_CIPHERTEXTBYTES];

unsigned char block[mctiny_BLOCKBYTES];
unsigned char ksession[32];

static long long phase;
static long long piecepos;
static long long rowpos;
static long long colpos;

void cookie0_prepare(void)
{
  kcookie_latest();
  /* kcookie is "s_m" in spec */

  hash(kcookie_hash,kcookie,32);
  /* kcookie_hash is "hash(s_m)" in spec */

  cookienonce[sizeof cookienonce-2] = 1;
  cookienonce[sizeof cookienonce-1] = 0;

  packet_clear();
  packet_append(kmaster,sizeof kmaster);
  packet_append(seed,sizeof seed);

  packet_encrypt(cookienonce,kcookie_hash);

  packet_append(kcookie+32,1);
  /* spec says "m mod 8".
     how this is encoded:
     kcookie[32] adds random multiple of 8.
     this prevents client from enforcing 0...7.
     this allows server to vary the 8.
  */

  packet_outgoing(cookie0,sizeof cookie0);
}

void phaseandpos_from_nonce(void)
{
  unsigned int nonce0,nonce1;

  phase = -1;
  rowpos = 0;
  colpos = 0;
  piecepos = 0;

  nonce0 = nonce[sizeof nonce-2];
  nonce1 = nonce[sizeof nonce-1];

  if (nonce0&1) return;

  if (!(nonce1&64)) {
    if (nonce0) return;
    if (nonce1) return;
    if (udplen != mctiny_QUERY0BYTES) return;
    phase = 0;
    return;
  }
  if (!(nonce1&32)) {
    rowpos = 127&(nonce0/2);
    colpos = 31&nonce1;
    if (rowpos >= mctiny_ROWBLOCKS) return;
    if (colpos >= mctiny_COLBLOCKS) return;
    if (nonce0 != 2*rowpos) return;
    if (nonce1 != 64+colpos) return;
    if (udplen != mctiny_QUERY1BYTES) return;
    phase = 1;
    return;
  }
  if (!(nonce1&16)) {
    piecepos = 127&(nonce0/2);
    if (piecepos >= mctiny_PIECES) return;
    if (nonce0 != 2*piecepos) return;
    if (nonce1 != 64+32) return;
    if (udplen != mctiny_QUERY2BYTES) return;
    phase = 2;
    return;
  }

  if (nonce1 != 255) return;
  if (nonce0 != 254) return;
  if (udplen != mctiny_QUERY3BYTES) return;
  phase = 3;
  return;
}

void serve(int s)
{
  struct sockaddr_storage clientaddr;
  socklen_t clientaddrlen;
  long long i,j;

  for (;;) {
    clientaddrlen = sizeof clientaddr;
    udplen = recvfrom(s,udp,sizeof udp,0,(struct sockaddr *) &clientaddr,&clientaddrlen);
    if (udplen > sizeof udp) continue;

    cycles -= cpucycles();

    packet_incoming(udp,udplen);
    packet_extract(nonce,sizeof nonce);

    phaseandpos_from_nonce();
    if (phase < 0) continue;

    if (phase == 0) {
      packet_extract(ciphertext,sizeof ciphertext);
      packet_extract(serverpkhash,sizeof serverpkhash);

      if (serversk_from_hash() != 0) continue;
      mctiny_dec(kmaster,ciphertext,serversk); /* cannot fail */
      if (packet_decrypt(nonce,kmaster) != 0) {
        /* silently reject invalid packets */
        continue;
      }
      packet_extract(extensions,sizeof extensions);
      if (!packet_isok()) continue;

      do
        randombytes(seed,sizeof seed);
      while (!mctiny_seedisvalid(seed));

      randombytes(cookienonce,sizeof cookienonce);
      cookie0_prepare();
      memcpy(nonce,cookienonce,sizeof nonce);
      goto outgoingpacket;
    }
    
    /* --- decrypt cookie0, obtaining kmaster etc. */

    memcpy(cookienonce,nonce,sizeof nonce);
    cookienonce[sizeof cookienonce-2] = 1;
    cookienonce[sizeof cookienonce-1] = 0;

    packet_extract(cookie0,sizeof cookie0);
    packet_incoming(cookie0,sizeof cookie0);
    packet_extract(kcookie+32,1);
    kcookie_fromid();
    hash(kcookie_hash,kcookie,32);
    if (packet_decrypt(cookienonce,kcookie_hash) != 0) {
      /* silently reject invalid packets */
      continue;
    }
    packet_extract(seed,sizeof seed);
    packet_extract(kmaster,sizeof kmaster);
    if (!packet_isok()) continue;

    /* --- use kmaster to decrypt the query; bump nonce */

    packet_incoming(udp,udplen);
    packet_extract(nonce,sizeof nonce);
    packet_extract(cookie0,sizeof cookie0);
    if (packet_decrypt(nonce,kmaster) != 0) {
      /* silently reject invalid packets */
      continue;
    }
    nonce[sizeof nonce-2] += 1;

    /* --- extract data from the query */
    
    if (phase == 1) {
      packet_extract(block,sizeof block);
    } else if (phase == 2) {
      for (j = mctiny_V-1;j >= 0;--j)
        for (i = mctiny_COLBLOCKS-1;i >= 0;--i)
          packet_extract(cookie1[j][i],sizeof cookie1[j][i]);
    } else if (phase == 3) {
      packet_extract(synd3,mctiny_COLBYTES);
    }

    if (!packet_isok()) continue;

    /* --- decrypt cookies and process query */

    if (phase == 1) {
      cyclesselected -= cpucycles();
      mctiny_seed2e(e,seed);
      mctiny_eblock2syndrome(synd1,e,block,colpos);
      cyclesselected += cpucycles();
    } else if (phase == 2) {
      mctiny_seed2e(e,seed);
      mctiny_pieceinit(synd2,e,piecepos);
      for (j = 0;j < mctiny_V;++j) {
        rowpos = mctiny_V*piecepos+j;
        if (rowpos >= mctiny_ROWBLOCKS) continue;
        for (i = 0;i < mctiny_COLBLOCKS;++i) {
          packet_incoming(cookie1[j][i],sizeof cookie1[j][i]);
          packet_extract(kcookie+32,1);
          kcookie_fromid();
          kcookie_hash_master();
          cookienonce[sizeof cookienonce-2] = rowpos*2+1;
          cookienonce[sizeof cookienonce-1] = 64+i;
          if (packet_decrypt(cookienonce,kcookie_hash) != 0) {
            /* silently reject invalid packets */
            goto packetdone;
          }
          packet_extract(synd1,mctiny_YBYTES);
          if (!packet_isok()) goto packetdone; /* internal bug */
          mctiny_pieceabsorb(synd2,synd1,j);
        }
      }
    } else { /* phase == 3 */
      mctiny_seed2e(e,seed);
      mctiny_finalize(ciphertext,ksession,synd3,e);
      /* ksession is "Z" in spec */
    }

    /* --- regenerate cookie0 */

    if (phase < 3)
      if (!kcookie_islatest())
        cookie0_prepare();

    /* --- create outgoing cookie */

    if (phase == 1) {
      kcookie_hash_master();
      packet_clear();
      packet_append(synd1,mctiny_YBYTES);
      packet_encrypt(nonce,kcookie_hash);
      packet_append(kcookie+32,1);
      packet_outgoing(cookie1[0][0],sizeof cookie1[0][0]);
    }

    randombytes(nonce,sizeof nonce-2);
    
    if (phase == 3) {
      hash(kcookie_hash,kcookie,32);
      packet_clear();
      packet_append(ksession,sizeof ksession);
      packet_encrypt(nonce,kcookie_hash);
      packet_append(kcookie+32,1);
      packet_outgoing(cookie9,sizeof cookie9);
    }

    /* --- create outgoing packet */
    outgoingpacket: /* phase==0 rejoins here */

    packet_clear();

    if (phase < 3) {
      packet_append(cookie0,sizeof cookie0);
      if (phase == 1)
        packet_append(cookie1[0][0],sizeof cookie1[0][0]);
      if (phase == 2)
        packet_append(synd2,sizeof synd2);
    } else {
      packet_append(cookie9,sizeof cookie9);
      packet_append(ciphertext,sizeof ciphertext);
    }

    packet_encrypt(nonce,kmaster);
    packet_append(nonce,sizeof nonce);

    if (phase == 0) udplen = mctiny_REPLY0BYTES;
    else if (phase == 1) udplen = mctiny_REPLY1BYTES;
    else if (phase == 2) udplen = mctiny_REPLY2BYTES;
    else /* phase == 3 */ udplen = mctiny_REPLY3BYTES;

    packet_outgoing(udp,udplen);

    cycles += cpucycles();

    sendto(s,udp,udplen,0,(struct sockaddr *) &clientaddr,clientaddrlen);

    if (phase == 3)  {
      fprintf(stderr,"server ksession %02x...%02x cycles %lld %lld\n",ksession[0],ksession[31],cycles,cyclesselected);
      cycles = 0;
      cyclesselected = 0;
    }

    packetdone: ;
  }
}

void die_usage(void)
{
  fprintf(stderr,"%s: usage: %s statedir serveraddr serverport\n",progname,progname);
  exit(100);
}

char *statedir;
char printip[NI_MAXHOST];
char printport[NI_MAXSERV];

int main(int argc,char **argv)
{
  const char *serveraddr = 0;
  const char *serverport = 0;
  struct addrinfo hints;
  struct addrinfo *addrhead;
  struct addrinfo *addr;
  int bound;
  int s;
  int r;

  if (!*argv++) die_usage();
  statedir = *argv;
  if (!*argv++) die_usage();
  serveraddr = *argv;
  if (!*argv++) die_usage();
  serverport = *argv;
  if (!*argv++) die_usage();

  if (chdir(statedir) == -1) {
    fprintf(stderr,"%s: fatal: unable to chdir to %s: %s\n",progname,statedir,strerror(errno));
    return 111;
  }
  if (chdir("secret") == -1) {
    fprintf(stderr,"%s: fatal: unable to chdir to %s/secret: %s\n",progname,statedir,strerror(errno));
    return 111;
  }

  memset(&hints,0,sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE;

  r = getaddrinfo(serveraddr,serverport,&hints,&addrhead);
  if (r != 0) {
    fprintf(stderr,"%s: fatal: getaddrinfo %s %s failed: %s\n",progname,serveraddr,serverport,gai_strerror(r));
    exit(111);
  }

  bound = 0;
  for (addr = addrhead;addr;addr = addr->ai_next) {
    s = socket(addr->ai_family,addr->ai_socktype,addr->ai_protocol);
    if (s == -1) {
      fprintf(stderr,"%s: warning: socket %d,%d,%d failed: %s\n"
        ,progname
        ,addr->ai_family,addr->ai_socktype,addr->ai_protocol
        ,strerror(errno));
      continue;
    }
    if (bind(s,addr->ai_addr,addr->ai_addrlen) == -1) {
      const char *bindfailure = strerror(errno);
      r = getnameinfo(addr->ai_addr,addr->ai_addrlen,printip,sizeof printip,printport,sizeof printport,NI_NUMERICHOST | NI_NUMERICSERV);
      if (r == 0) {
        fprintf(stderr,"%s: warning: bind %d,%d,%d %s %s failed: %s\n"
          ,progname
          ,addr->ai_family,addr->ai_socktype,addr->ai_protocol
          ,printip,printport
          ,bindfailure);
      } else {
        fprintf(stderr,"%s: warning: bind %d,%d,%d failed: %s\n"
          ,progname
          ,addr->ai_family,addr->ai_socktype,addr->ai_protocol
          ,bindfailure);
        fprintf(stderr,"%s: warning: getnameinfo failed: %s\n",progname,gai_strerror(r));
      }
      continue;
    }
    bound = 1;
    break;
  }

  freeaddrinfo(addrhead);

  if (!bound) {
    fprintf(stderr,"%s: fatal: unable to bind to any address\n",progname);
    exit(111);
  }

  if (bound)
    serve(s);

  return 0;
}
