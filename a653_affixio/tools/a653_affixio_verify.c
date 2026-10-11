/* a653_affixio_verify <partition> <image> [manifest] [--bench N]
 * Trust from env (see a653_affixio.h). Exit 0 = verified, 1 = refused (reason on stderr). */
#define _POSIX_C_SOURCE 199309L
#include "a653_affixio.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
static int cmp(const void *a, const void *b){ long long x=*(const long long*)a, y=*(const long long*)b; return (x>y)-(x<y); }
int main(int argc, char **argv){
  a653_affixio_trust_t t; const char *reason="?"; char man[1024]; int bench=0, i;
  if (argc<3){ fprintf(stderr,"usage: %s <partition> <image> [manifest] [--bench N]\n",argv[0]); return 2; }
  for (i=3;i<argc;i++) if(!strcmp(argv[i],"--bench") && i+1<argc) bench=atoi(argv[i+1]);
  if (argc>3 && strncmp(argv[3],"--",2)) snprintf(man,sizeof man,"%s",argv[3]); else snprintf(man,sizeof man,"%s.a653sig",argv[2]);
  if (a653_affixio_trust_from_env(&t,&reason)){ fprintf(stderr,"refused: %s\n",reason); return 1; }
  if (!bench){ int r=a653_affixio_verify_image(&t,argv[1],argv[2],man,&reason); fprintf(r?stderr:stdout,"%s: %s\n",r?"refused":"verified",reason); return r?1:0; }
  { long long *ns=malloc(sizeof(long long)*(size_t)bench); struct timespec a,b; double sum=0;
    t.state_path=NULL; /* rollback state off for timing */
    for (i=0;i<bench;i++){ clock_gettime(CLOCK_MONOTONIC,&a); if(a653_affixio_verify_image(&t,argv[1],argv[2],man,&reason)){fprintf(stderr,"refused: %s\n",reason);return 1;}
      clock_gettime(CLOCK_MONOTONIC,&b); ns[i]=(b.tv_sec-a.tv_sec)*1000000000LL+(b.tv_nsec-a.tv_nsec); sum+=(double)ns[i]; }
    qsort(ns,(size_t)bench,sizeof *ns,cmp);
    printf("{\"n\":%d,\"mean_us\":%.1f,\"min_us\":%.1f,\"p50_us\":%.1f,\"p99_us\":%.1f,\"max_us\":%.1f,\"jitter_p99_minus_min_us\":%.1f}\n",bench,sum/bench/1e3,
      ns[0]/1e3,ns[bench/2]/1e3,ns[(int)(bench*0.99)]/1e3,ns[bench-1]/1e3,(ns[(int)(bench*0.99)]-ns[0])/1e3);
    free(ns); }
  return 0;
}
