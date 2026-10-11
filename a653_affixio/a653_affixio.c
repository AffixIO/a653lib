/* a653_affixio.c -- see a653_affixio.h. Manifest file (written by sidecar/sign.mjs):
 *   A653AFFIX1
 *   msg <base64 of the exact signed bytes: "affix.sdk.local-signature.v2\n" + canonical JSON>
 *   sig <base64 ML-DSA-65 signature>
 *   [srv_payload <base64 of the exact AffixIO attest payload JSON>]
 *   [srv_sig <base64 ML-DSA-65 over sha256(srv_payload)>]
 * The signed JSON is produced from controlled values, so the parser below is deliberately
 * strict: any backslash or duplicated key is a refusal, not a guess. */
#include "a653_affixio.h"
#include "api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_MSG 4096
#define MAX_SIG 3309
static const char PREFIX[] = "affix.sdk.local-signature.v2\n";

/* ---- SHA-256 (FIPS 180-4), streaming, no allocation ---- */
typedef struct { uint32_t h[8]; uint64_t n; uint8_t b[64]; size_t l; } sha_t;
static const uint32_t K[64] = {
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
#define R(x,n) (((x)>>(n))|((x)<<(32-(n))))
static void sha_blk(sha_t *s, const uint8_t *p) {
  uint32_t w[64], a,b,c,d,e,f,g,h; int i;
  for (i=0;i<16;i++) w[i]=(uint32_t)p[4*i]<<24|(uint32_t)p[4*i+1]<<16|(uint32_t)p[4*i+2]<<8|p[4*i+3];
  for (;i<64;i++) w[i]=(R(w[i-2],17)^R(w[i-2],19)^(w[i-2]>>10))+w[i-7]+(R(w[i-15],7)^R(w[i-15],18)^(w[i-15]>>3))+w[i-16];
  a=s->h[0];b=s->h[1];c=s->h[2];d=s->h[3];e=s->h[4];f=s->h[5];g=s->h[6];h=s->h[7];
  for (i=0;i<64;i++){ uint32_t t1=h+(R(e,6)^R(e,11)^R(e,25))+((e&f)^(~e&g))+K[i]+w[i];
    uint32_t t2=(R(a,2)^R(a,13)^R(a,22))+((a&b)^(a&c)^(b&c)); h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2; }
  s->h[0]+=a;s->h[1]+=b;s->h[2]+=c;s->h[3]+=d;s->h[4]+=e;s->h[5]+=f;s->h[6]+=g;s->h[7]+=h;
}
static void sha_init(sha_t *s){ static const uint32_t iv[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19}; memcpy(s->h,iv,32); s->n=0; s->l=0; }
static void sha_upd(sha_t *s, const uint8_t *d, size_t n){ s->n+=n; while(n){ size_t k=64-s->l; if(k>n)k=n; memcpy(s->b+s->l,d,k); s->l+=k; d+=k; n-=k; if(s->l==64){sha_blk(s,s->b); s->l=0;} } }
static void sha_fin(sha_t *s, uint8_t o[32]){ uint64_t bits=s->n*8; uint8_t z=0x80; int i; sha_upd(s,&z,1); z=0; while(s->l!=56) sha_upd(s,&z,1);
  for(i=7;i>=0;i--){ z=(uint8_t)(bits>>(8*i)); sha_upd(s,&z,1);} for(i=0;i<8;i++){o[4*i]=(uint8_t)(s->h[i]>>24);o[4*i+1]=(uint8_t)(s->h[i]>>16);o[4*i+2]=(uint8_t)(s->h[i]>>8);o[4*i+3]=(uint8_t)s->h[i];} }
void a653_affixio_sha256(const uint8_t *d, size_t n, uint8_t out[32]){ sha_t s; sha_init(&s); sha_upd(&s,d,n); sha_fin(&s,out); }
static void hex(const uint8_t *in, size_t n, char *out){ static const char H[]="0123456789abcdef"; size_t i; for(i=0;i<n;i++){out[2*i]=H[in[i]>>4];out[2*i+1]=H[in[i]&15];} out[2*n]=0; }

/* ---- base64 (strict: standard alphabet, padding optional at end only) ---- */
size_t a653_affixio_b64dec(const char *in, uint8_t *out, size_t cap){
  uint32_t acc=0; int bits=0; size_t n=0; const char *p;
  for (p=in; *p && *p!='='; p++){ int v; char c=*p;
    if(c>='A'&&c<='Z')v=c-'A'; else if(c>='a'&&c<='z')v=c-'a'+26; else if(c>='0'&&c<='9')v=c-'0'+52; else if(c=='+')v=62; else if(c=='/')v=63; else return 0;
    acc=(acc<<6)|(uint32_t)v; bits+=6; if(bits>=8){ bits-=8; if(n>=cap) return 0; out[n++]=(uint8_t)(acc>>bits); } }
  while (*p=='=') p++;
  return *p ? 0 : n;
}

/* ---- strict field extraction from controlled JSON ---- */
static const char *field(const char *j, const char *key, int *count){
  char pat[80]; const char *p=j, *hit=NULL; int c=0;
  snprintf(pat,sizeof pat,"\"%s\":",key);
  while ((p=strstr(p,pat))!=NULL){ c++; hit=p+strlen(pat); p+=1; }
  *count=c; return hit;
}
static int str_field(const char *j, const char *key, char *out, size_t cap){
  int c; const char *v=field(j,key,&c); size_t n=0;
  if (c!=1 || *v!='"') return -1;
  v++;
  while (*v && *v!='"'){ if(n+1>=cap) return -1; out[n++]=*v++; }
  if (*v!='"') return -1;
  out[n]=0;
  return 0;
}
static int num_field(const char *j, const char *key, long long *out){
  int c; const char *v=field(j,key,&c); char *e;
  if (c!=1) return -1;
  *out=strtoll(v,&e,10);
  return (e==v || *out<0) ? -1 : 0;
}
static int lit_field(const char *j, const char *key, const char *lit){
  int c; const char *v=field(j,key,&c); return (c==1 && strncmp(v,lit,strlen(lit))==0) ? 0 : -1;
}

/* ---- manifest I/O ---- */
typedef struct { uint8_t msg[MAX_MSG+1]; size_t msg_n; uint8_t sig[MAX_SIG]; size_t sig_n;
                 uint8_t sp[MAX_MSG+1]; size_t sp_n; uint8_t ssig[MAX_SIG]; size_t ssig_n; } manifest_t;
static int read_manifest(const char *path, manifest_t *m){
  static char line[8192]; FILE *f=fopen(path,"r"); int first=1;
  if (!f) return -1;
  memset(m,0,sizeof *m);
  while (fgets(line,sizeof line,f)){ char *nl=strchr(line,'\n'); if(!nl){fclose(f);return -1;} *nl=0;
    if (first){ if(strcmp(line,"A653AFFIX1")){fclose(f);return -1;} first=0; continue; }
    if (!strncmp(line,"msg ",4)) m->msg_n=a653_affixio_b64dec(line+4,m->msg,MAX_MSG);
    else if (!strncmp(line,"sig ",4)) m->sig_n=a653_affixio_b64dec(line+4,m->sig,MAX_SIG);
    else if (!strncmp(line,"srv_payload ",12)) m->sp_n=a653_affixio_b64dec(line+12,m->sp,MAX_MSG);
    else if (!strncmp(line,"srv_sig ",8)) m->ssig_n=a653_affixio_b64dec(line+8,m->ssig,MAX_SIG);
    else if (line[0]) { fclose(f); return -1; } }
  fclose(f);
  if (first || !m->msg_n || m->sig_n!=MAX_SIG) return -1;
  m->msg[m->msg_n]=0; m->sp[m->sp_n]=0; return 0;
}
static int hash_file(const char *path, char out_hex[65]){
  static uint8_t buf[16384]; uint8_t d[32]; sha_t s; size_t n; FILE *f=fopen(path,"rb");
  if (!f) return -1;
  sha_init(&s);
  while ((n=fread(buf,1,sizeof buf,f))>0) sha_upd(&s,buf,n);
  if (ferror(f)){fclose(f);return -1;} fclose(f); sha_fin(&s,d); hex(d,32,out_hex); return 0;
}

/* ---- anti-rollback state: lines "<partition> <counter>" ---- */
static int rollback_check(const char *state, const char *part, long long ctr, int commit){
  char lines[64][96]; int n=0, i, found=-1; long long cur=-1; FILE *f;
  if (!state) return 0;
  if ((f=fopen(state,"r"))){ char nm[64]; long long v; while(n<64 && fgets(lines[n],sizeof lines[n],f)){ if(sscanf(lines[n],"%63s %lld",nm,&v)==2 && !strcmp(nm,part)){found=n;cur=v;} n++; } fclose(f); }
  if (ctr < cur) return -1;
  if (!commit || ctr==cur) return 0;
  if (found<0){ if(n>=64) return -2; found=n++; }
  snprintf(lines[found],sizeof lines[found],"%s %lld\n",part,ctr);
  { char tmp[512]; snprintf(tmp,sizeof tmp,"%s.tmp",state); f=fopen(tmp,"w"); if(!f) return -2;
    for(i=0;i<n;i++) fputs(lines[i],f);
    if(fflush(f)||fclose(f)) return -2;
    if(rename(tmp,state)) return -2; }
  return 0;
}

int a653_affixio_verify_image(const a653_affixio_trust_t *t, const char *partition,
                              const char *image_path, const char *manifest_path, const char **reason){
  static manifest_t m; char v[160], img[65]; const char *j; long long ctr;
#define FAIL(r) do { *reason=(r); return -1; } while(0)
  if (!t || !partition || !image_path || !manifest_path) FAIL("bad_args");
  if (read_manifest(manifest_path,&m)) FAIL("manifest_unreadable");
  if (PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(m.sig,m.sig_n,m.msg,m.msg_n,t->pk)) FAIL("signature_invalid");
  if (memcmp(m.msg,PREFIX,sizeof PREFIX-1)) FAIL("not_v2_envelope");
  j=(const char*)m.msg+sizeof PREFIX-1;
  if (strchr(j,'\\') || strlen(j)!=m.msg_n-(sizeof PREFIX-1)) FAIL("noncanonical");
  if (lit_field(j,"domain","\"affix.sdk.local-signature.v2\"")) FAIL("domain");
  if (str_field(j,"key_id",v,sizeof v) || strcmp(v,t->key_id)) FAIL("untrusted_key_id");
  if (str_field(j,"schema",v,sizeof v) || strcmp(v,"a653.partition-manifest.v1")) FAIL("schema");
  if (str_field(j,"partition",v,sizeof v) || strcmp(v,partition)) FAIL("partition_mismatch");
  if (hash_file(image_path,img)) FAIL("image_unreadable");
  if (str_field(j,"image_sha256",v,sizeof v) || strcmp(v,img)) FAIL("image_hash_mismatch");
  if (num_field(j,"counter",&ctr)) FAIL("counter");
  if (t->require_server){
    char pd[80], spd[80]; uint8_t d[32]; const char *s=(const char*)m.sp;
    if (!m.sp_n || m.ssig_n!=MAX_SIG) FAIL("server_attestation_missing");
    a653_affixio_sha256(m.sp,m.sp_n,d);
    if (PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(m.ssig,m.ssig_n,d,32,t->server_pk)) FAIL("server_signature_invalid");
    if (strchr(s,'\\') || strlen(s)!=m.sp_n) FAIL("server_noncanonical");
    if (lit_field(s,"domain","\"affixio.attest.verified-proof.v1\"") || lit_field(s,"valid","true") ||
        lit_field(s,"decision","\"yes\"") || lit_field(s,"circuit_id","\"simple_yesno\"")) FAIL("server_payload");
    if (str_field(s,"proof_digest",spd,sizeof spd) || str_field(j,"affixio_proof_digest",pd,sizeof pd) || strcmp(pd,spd)) FAIL("server_not_bound");
  }
  { int r=rollback_check(t->state_path,partition,ctr,0); if(r==-1) FAIL("rollback"); if(r) FAIL("state_error"); }
  if (rollback_check(t->state_path,partition,ctr,1)) FAIL("state_error");
  *reason="ok"; return 0;
#undef FAIL
}

static int load_pk(const char *path, uint8_t pk[A653_AFFIXIO_PK_BYTES]){
  static char b[4096]; FILE *f; size_t n;
  if (!path || !(f=fopen(path,"r"))) return -1;
  n=fread(b,1,sizeof b-1,f); fclose(f); b[n]=0;
  while (n && (b[n-1]=='\n'||b[n-1]=='\r'||b[n-1]==' ')) b[--n]=0;
  return a653_affixio_b64dec(b,pk,A653_AFFIXIO_PK_BYTES)==A653_AFFIXIO_PK_BYTES ? 0 : -1;
}
int a653_affixio_trust_from_env(a653_affixio_trust_t *t, const char **reason){
  const char *kid=getenv("A653_AFFIXIO_KEY_ID"), *skp=getenv("A653_AFFIXIO_SERVER_PUBKEY_FILE");
  memset(t,0,sizeof *t);
  if (load_pk(getenv("A653_AFFIXIO_PUBKEY_FILE"),t->pk)) { *reason="pinned_key_missing"; return -1; }
  if (!kid || strlen(kid)>=sizeof t->key_id) { *reason="key_id_missing"; return -1; }
  strcpy(t->key_id,kid);
  t->state_path=getenv("A653_AFFIXIO_STATE");
  if (skp && *skp){ const char *sk=getenv("A653_AFFIXIO_SERVER_KEY_ID");
    if (load_pk(skp,t->server_pk) || !sk || strlen(sk)>=sizeof t->server_key_id){ *reason="server_key_missing"; return -1; }
    strcpy(t->server_key_id,sk); t->require_server=1; }
  return 0;
}
int a653_affixio_check_spawn(char *const argv[], int argc, const char **reason){
  a653_affixio_trust_t t; char man[1024]; int i;
  if (a653_affixio_trust_from_env(&t,reason)) return -1;
  for (i=0;i<argc && i<2;i++){ const char *p=argv[i], *base=strrchr(p,'/'); base=base?base+1:p;
    if (i==1 && (strlen(p)<5 || strcmp(p+strlen(p)-5,".wasm"))) break;
    if (snprintf(man,sizeof man,"%s.a653sig",p)>=(int)sizeof man){ *reason="path_too_long"; return -1; }
    if (a653_affixio_verify_image(&t,base,p,man,reason)) return -1; }
  return 0;
}
