/* Exercises a653_affixio_check_spawn exactly as start_partition_process calls it. */
#include "a653_affixio.h"
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv){
  const char *reason="?"; int r;
  if (argc<2) return 2;
  r=a653_affixio_check_spawn(argv+1,argc-1,&reason);
  printf("%s %s\n",r?"refused":"allowed",reason);
  return r?1:0;
}
