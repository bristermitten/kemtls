#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <dirent.h>
#include "hash.h"

const char progname[] = "mctiny-rotate";

void die_usage(void)
{
  fprintf(stderr,"%s: usage: %s statedir\n",progname,progname);
  exit(100);
}

char *statedir;
const char subdir[] = "secret/temporary-cookie-keys";

void lock(void)
{
  int fdlock = open("lock",O_RDWR|O_CREAT,0600);
  if (fdlock < 0) {
    fprintf(stderr,"%s: fatal: unable to open %s/%s/lock: %s\n",progname,statedir,subdir,strerror(errno));
    exit(111);
  }
  if (flock(fdlock,LOCK_EX) < 0) {
    fprintf(stderr,"%s: fatal: unable to lock %s/%s/lock: %s\n",progname,statedir,subdir,strerror(errno));
    exit(111);
  }
}

const char *oknames[] = { ".", "..", "lock", "latest", "0", "1", "2", "3", "4", "5", "6", "7", 0 } ;

void cleanup(void)
{
  DIR *dir;
  struct dirent *dirent;
  long long i;

  dir = opendir(".");
  if (!dir) {
    fprintf(stderr,"%s: fatal: unable to read %s/%s: %s\n",progname,statedir,subdir,strerror(errno));
    exit(111);
  }

  for (;;) {
    errno = 0;
    dirent = readdir(dir);
    if (!dirent) {
      if (errno) {
        fprintf(stderr,"%s: fatal: unable to read %s/%s: %s\n",progname,statedir,subdir,strerror(errno));
        exit(111);
      }
      break;
    }
    for (i = 0;oknames[i];++i)
      if (!strcmp(oknames[i],dirent->d_name))
        break;
    if (!oknames[i])
      if (unlink(dirent->d_name) < 0)
        fprintf(stderr,"%s: alert: unable to remove stray %s/%s: %s\n",progname,statedir,subdir,strerror(errno));
  }
    
  closedir(dir);
}

/* extract cookie number from string */
/* -1: failure */
long long parselink(char *x)
{
  long long result;

  result = x[0]-'0';
  if (result < 0) result = -1;
  if (result > 7) result = -1;
  if (x[1]) result = -1;
  return result;
}

char fntmp[10];
char fn[10];

unsigned char cookiekey[33];

int main(int argc,char **argv)
{
  long long cookiekeynum;
  int fd;

  if (!argv[0]) die_usage();
  if (!argv[1]) die_usage();
  statedir = argv[1];

  umask(077);

  if (chdir(statedir) < 0) {
    fprintf(stderr,"%s: fatal: unable to chdir to %s: %s\n",progname,statedir,strerror(errno));
    exit(111);
  }
  if (chdir(subdir) < 0) {
    fprintf(stderr,"%s: fatal: unable to chdir to %s/%s: %s\n",progname,statedir,subdir,strerror(errno));
    exit(111);
  }

  lock();
  cleanup();

  if (readlink("latest",fn,sizeof fn) >= sizeof fn) {
    fprintf(stderr,"%s: fatal: unable to readlink %s/%s/latest: %s\n",progname,statedir,subdir,strerror(errno));
    exit(111);
  }
  cookiekeynum = parselink(fn);
  if (cookiekeynum == -1) {
    fprintf(stderr,"%s: alert: weird %s/%s/latest\n",progname,statedir,subdir);
    exit(111);
  }

  fd = open("latest",O_RDONLY);
  if (fd < 0) {
    fprintf(stderr,"%s: fatal: unable to open %s/%s/latest: %s\n",progname,statedir,subdir,strerror(errno));
    exit(111);
  }
  if (read(fd,cookiekey,sizeof cookiekey) != sizeof cookiekey) {
    fprintf(stderr,"%s: fatal: unable to read %s/%s/latest: %s\n",progname,statedir,subdir,strerror(errno));
    exit(111);
  }
  close(fd);

  cookiekeynum += 1;
  cookiekeynum &= 7;

  if (snprintf(fntmp,sizeof fntmp,"%lld.tmp",cookiekeynum) >= sizeof fntmp) {
    fprintf(stderr,"%s: fatal: internal snprintf error\n",progname);
    exit(100);
  }
  if (snprintf(fn,sizeof fn,"%lld",cookiekeynum) >= sizeof fn) {
    fprintf(stderr,"%s: fatal: internal snprintf error\n",progname);
    exit(100);
  }

  /* XXX: document how this is length-separated from other hashes */
  cookiekey[32] = 128;
  hash(cookiekey+1,cookiekey,33);
  hash(cookiekey,cookiekey,33);

  cookiekey[32] &= ~7;
  cookiekey[32] += cookiekeynum;

  fd = open(fntmp,O_WRONLY|O_CREAT,0600);
  if (fd < 0) {
    fprintf(stderr,"%s: fatal: unable to create %s/%s/%s: %s\n",progname,statedir,subdir,fntmp,strerror(errno));
    exit(111);
  }

  errno = EINTR;
  if (write(fd,cookiekey,sizeof cookiekey) < sizeof cookiekey) {
    /* XXX: assuming that write of this size is atomic */
    fprintf(stderr,"%s: fatal: unable to create %s/%s/%s: %s\n",progname,statedir,subdir,fntmp,strerror(errno));
    exit(111);
  }
  if (fsync(fd) < 0) {
    fprintf(stderr,"%s: fatal: unable to create %s/%s/%s: %s\n",progname,statedir,subdir,fntmp,strerror(errno));
    exit(111);
  }
  close(fd);

  if (rename(fntmp,fn) == -1) {
    fprintf(stderr,"%s: fatal: unable to move %s/%s/%s to %s: %s\n",progname,statedir,subdir,fntmp,fn,strerror(errno));
    exit(111);
  }

  if (symlink(fn,"latest-tmp") == -1) {
    fprintf(stderr,"%s: fatal: unable to link %s/%s/latest-tmp to %s: %s\n",progname,statedir,subdir,fn,strerror(errno));
    exit(111);
  }
  if (rename("latest-tmp","latest") == -1) {
    fprintf(stderr,"%s: fatal: unable to move %s/%s/latest-tmp to latest: %s\n",progname,statedir,subdir,strerror(errno));
    exit(111);
  }

  fd = open(".",O_RDONLY);
  if (fd == -1) {
    fprintf(stderr,"%s: fatal: unable to open %s/%s: %s\n",progname,statedir,subdir,strerror(errno));
    exit(111);
  }
  if (fsync(fd) < 0) {
    fprintf(stderr,"%s: fatal: unable to sync %s/%s: %s\n",progname,statedir,subdir,strerror(errno));
    exit(111);
  }
  close(fd);

  exit(0);
}
