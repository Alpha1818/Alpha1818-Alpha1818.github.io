#define WNOHANG 0100
#define F_OK    0
#define X_OK    1
#define W_OK    2
#define R_OK    4
#define setuid(x)
#define setgid(x)
#define geteuid()   666
#define getuid()    666
#define getgid()    666
#define getpwnam(x) NULL
#define chroot(x)   0

typedef long clock_t;

struct tms {
  clock_t tms_utime;
  clock_t tms_stime;
  clock_t tms_cutime;
  clock_t tms_cstime;
};

#define times(x)
#define sysconf(x)  1
#define sleep(x)
#define dup(x)
