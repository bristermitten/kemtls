#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/stat.h>
#include "mctiny.h"
#include "hash.h"
#include "randombytes.h"

const char progname[] = "mctiny-master";

void die_usage(void)
{
  fprintf(stderr,"%s: usage: %s statedir\n",progname,progname);
  exit(100);
}

char *statedir;

void syncdir(const char *subdir)
{
  int fd = open(subdir,O_RDONLY);
  if (fd < 0) {
    fprintf(stderr,"%s: fatal: unable to open %s/%s: %s\n",progname,statedir,subdir,strerror(errno));
    exit(111);
  }
  if (fsync(fd) < 0) {
    fprintf(stderr,"%s: fatal: unable to sync %s/%s: %s\n",progname,statedir,subdir,strerror(errno));
    exit(111);
  }
  close(fd);
}

void writesyncfile(const char *fn,unsigned char *data,long long datalen)
{
  FILE *fi = fopen(fn,"w");
  if (!fi) {
    fprintf(stderr,"%s: fatal: unable to create %s/%s: %s\n",progname,statedir,fn,strerror(errno));
    exit(111);
  }
  if (fwrite(data,datalen,1,fi) < 1) {
    fprintf(stderr,"%s: fatal: unable to write %s/%s: %s\n",progname,statedir,fn,strerror(errno));
    exit(111);
  }
  if (fflush(fi) < 0) {
    fprintf(stderr,"%s: fatal: unable to write %s/%s: %s\n",progname,statedir,fn,strerror(errno));
    exit(111);
  }
  if (fsync(fileno(fi)) < 0) {
    fprintf(stderr,"%s: fatal: unable to write %s/%s: %s\n",progname,statedir,fn,strerror(errno));
    exit(111);
  }
  fclose(fi);
}

unsigned char serverpk[mctiny_PUBLICKEYBYTES];
unsigned char serversk[mctiny_SECRETKEYBYTES];

unsigned char serverpkhash[32];
char pkhashhex[65];
char fnpk[100];
char fnsk[100];

unsigned char cookiekey[33];

int main(int argc,char **argv)
{
  long long i;

  if (!argv[0]) die_usage();
  if (!argv[1]) die_usage();
  statedir = argv[1];

  umask(022);

  if (mkdir(statedir,0755) < 0) {
    fprintf(stderr,"%s: fatal: unable to create %s: %s\n",progname,statedir,strerror(errno));
    exit(111);
  }
  if (chdir(statedir) < 0) {
    fprintf(stderr,"%s: fatal: unable to chdir to %s: %s\n",progname,statedir,strerror(errno));
    exit(111);
  }

  if (mkdir("public",0755) < 0) {
    fprintf(stderr,"%s: fatal: unable to create %s/public: %s\n",progname,statedir,strerror(errno));
    exit(111);
  }
  if (mkdir("secret",0700) < 0) {
    fprintf(stderr,"%s: fatal: unable to create %s/secret: %s\n",progname,statedir,strerror(errno));
    exit(111);
  }
  if (mkdir("secret/long-term-keys",0700) < 0) {
    fprintf(stderr,"%s: fatal: unable to create %s/secret/long-term-keys: %s\n",progname,statedir,strerror(errno));
    exit(111);
  }
  if (mkdir("secret/temporary-cookie-keys",0700) < 0) {
    fprintf(stderr,"%s: fatal: unable to create %s/secret/temporary-cookie-keys: %s\n",progname,statedir,strerror(errno));
    exit(111);
  }

  if (mctiny_keypair(serverpk,serversk) != 0) {
    fprintf(stderr,"%s: fatal: internal error: keygen failed\n",progname);
    exit(111);
  }
  hash(serverpkhash,serverpk,sizeof serverpk);
  randombytes(cookiekey,sizeof cookiekey);
  cookiekey[32] &= ~7;

  for (i = 0;i < 32;++i) {
    int b = serverpkhash[i];
    pkhashhex[2*i] = "0123456789abcdef"[15&(b>>4)];
    pkhashhex[2*i+1] = "0123456789abcdef"[15&b];
  }
  pkhashhex[2*i] = 0;

  if (snprintf(fnpk,sizeof fnpk,"public/%s",pkhashhex) >= sizeof fnpk) {
    fprintf(stderr,"%s: fatal: internal error: snprintf failed\n",progname);
    exit(100);
  }
  if (snprintf(fnsk,sizeof fnsk,"secret/long-term-keys/%s",pkhashhex) >= sizeof fnsk) {
    fprintf(stderr,"%s: fatal: internal error: snprintf failed\n",progname);
    exit(100);
  }

  writesyncfile(fnpk,serverpk,sizeof serverpk);
  umask(077);
  writesyncfile(fnsk,serversk,sizeof serversk);
  writesyncfile("secret/temporary-cookie-keys/0",cookiekey,sizeof cookiekey);

  if (symlink("0","secret/temporary-cookie-keys/latest") < 0) {
    fprintf(stderr,"%s: fatal: unable to create %s/secret/temporary-cookie-keys/latest: %s\n",progname,statedir,strerror(errno));
    exit(111);
  }
  
  syncdir("secret/temporary-cookie-keys");
  syncdir("secret/long-term-keys");
  syncdir("secret");
  syncdir("public");
  syncdir(".");
  syncdir("..");

  return 0;
}
