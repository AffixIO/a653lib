/* Known-answer tests for the bundled SHA-256 and strict base64 decoder. */
#include "a653_affixio.h"
#include <stdio.h>
#include <string.h>
static int fails=0;
#define CHECK(c,m) do{ if(!(c)){ printf("FAIL %s\n",m); fails++; } else printf("ok   %s\n",m); }while(0)
int main(void){
  uint8_t d[32], o[16]; char h[65]; int i;
  static const char *abc="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
  a653_affixio_sha256((const uint8_t*)"abc",3,d); for(i=0;i<32;i++) sprintf(h+2*i,"%02x",d[i]);
  CHECK(!strcmp(h,abc),"sha256(abc)");
  a653_affixio_sha256((const uint8_t*)"",0,d); for(i=0;i<32;i++) sprintf(h+2*i,"%02x",d[i]);
  CHECK(!strcmp(h,"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),"sha256(empty)");
  CHECK(a653_affixio_b64dec("aGVsbG8=",o,sizeof o)==5 && !memcmp(o,"hello",5),"b64 hello");
  CHECK(a653_affixio_b64dec("aGV$bG8=",o,sizeof o)==0,"b64 rejects bad char");
  CHECK(a653_affixio_b64dec("aGVsbG8=x",o,sizeof o)==0,"b64 rejects data after padding");
  CHECK(a653_affixio_b64dec("aGVsbG8gd29ybGQhISE=",o,4)==0,"b64 rejects overflow");
  return fails?1:0;
}
