#include "../AES/aes.h"

void run_aes_shares_prg(byte *in,byte *out,byte *key,int n,int choice,int type,double *time,int nt);
void run_present_shares_prg(byte *in,byte*out,byte *key,int n,double *time,int nt);

double run_aes_share_bitslice8(byte in[16],byte out[16],byte key[16],byte n,int nt);
double run_present_shares_crv(byte *in,byte*out,byte *key,int n,int nt);

/************specific to aes third order************ */
 void run_aes_shares_third(byte *in, byte *out, byte *key, int n, int type, int nt, double time[11]);
 /**************specific to present third orde***************/
 void run_present_shares_third(byte *in,byte*out,byte *key,int n,double *time,int nt, int type);
 
/*****************specific to coron*****************/
void run_aes_common_share(byte in[16],byte out[16],byte key[16],int n,void (*subbyte_common_share_call)(byte *,byte *,int),int nt,double time[11]);
