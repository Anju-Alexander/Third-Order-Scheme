#include <stdio.h>

#include "AES/aes.h"
#include "AES/aes_htable_PRG.h"
#include "Util/driver_functions.h"
#include "PRESENT/present.h"
#include "Util/prg3.h"
#include "BITSLICE/bitslice.h"

#if TRNG  ==1
#include "MK64F12.h"
#endif

#define AES 1
#define PRESENT 2
//#define BITSLICE 3
#define CRV_present 4




//*******************main*****************************************

int main()
{
    /**********Input parameters for Higher-order LUT-based block cipher implementation********/

    int nt = 10; //Number of times to repeat experiments
    int shares = shares_N; // #Input shares. Set the parameter in common.h.
    int cipher = LRV; //Cipher can be AES or PRESENT or BITSLICE or CRV_present
    int scheme = VARIANT; //Set the parameter in common.h file. Type of LUT construction. normal--> NPRG  Increasing shares--> IPRG
    int type_PRG = MPRG; //Type of PRG to generate randoms, either robust-->RPRG or multiple-->MPRG

    double time[11]={0,0,0,0,0,0,0,0,0,0,0};// To hold offline and online execution clock cycle count
    double time_b[1]={0};
    int i,k,al;
/*
    printf("**********************************************\n");
    printf("Input choices\n");
    printf("Cipher: %d (1:AES 2:PRESENT 3:Bitslice 4:PRESENT_CRV)\n",cipher);
    printf("#shares: %d, Variant:%d  (1:Normal 0:Increasing shares) and PRG type: %d (2:robust 3:multiple PRG)\n",shares,scheme,type_PRG);
    printf("**********************************************\n");*/
  
	al=1;
	rand_in();
		if(cipher==BITSLICE)
		{
			int nt=1;
  byte n=shares_N;
  int i,j,k;
 


/***********Test Vectors***************/
  byte keyex[16]={0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};

  byte inex[16]={0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34};

  byte outex[16]={0x39,0x25,0x84,0x1d,0x02,0xdc,0x09,0xfb,0xdc,0x11,0x85,0x97,0x19,0x6a,0x0b,0x32};

  byte inex1[16]={0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xa,0xb,0xc,0xd,0xe,0xf,0x1};

  byte in[16],in1[16],in2[16],out[16],out1[16],out2[16];
  byte key[16],key1[16],key2[16];

  for(i=0;i<16;i++)
  {
    key[i]=keyex[i];
    key1[i]=keyex[i];
    key2[i]=keyex[i];
  }

  for(i=0;i<16;i++)
  {
     in[i]=inex[i];
     in1[i]=inex[i];
     in2[i]=inex[i];
  
	}	
	      //run_aes_w(in1,out1,key1,nt);
        run_bitslice(in1,out1,key1,nt);

      	run_bitslice_shares(in2,out2,key2,nt,time_b);
        for(i=0;i<16;i++)
       {
         if(out1[i]!=out2[i])
         {
           al=2;
           printf("unsuccessful execution...please check\n");
           //compare_output(out1,out2,16);
           break;

         }
       }
			 al=5;
      printf("successful execution of 32-bit bitslicing\n");

			
		    
		}
	
		if(cipher==PRESENT_THIRD||cipher==PRESENT_THIRD_PRG)
		{	
			
			 byte keyex[] ={0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
       byte inex[8]={0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};//{0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d};
       
			 byte in1[8],in2[8],out1[8],out2[8];
    	 byte key1[10],key2[10];
			 al=0;
			 
			 for(i=0;i<10;i++)
        {
            key1[i]=keyex[i];
            key2[i]=keyex[i];
        }


		    for(i=0;i<8;i++)
        {
            in1[i]=inex[i];//rand()%256;
            in2[i]=inex[i];

        }


		    for(k=0;k<8;k++)
        {
            out1[k]=0x0;
            out2[k]=0x0;
        }
				present(in1,out1,key1);
				run_present_shares_third(in2,out2,key2,shares,time,nt,cipher);
				if(compare_output(out1,out2,8))
        {
            printf("Successful execution of LUT-based PRESENT\n");
            /*
            #if TRNG==0
            printf("#Milli seconds: Off-line: %f and Online: %f\n ",time[0],time[1]);
            #else
            printf("#Clock_cycles: Off-line: %f and Online: %f\n ",time[0],time[1]);
            #endif
*/
        }

        else
            {
                printf("Unsuccessful execution :(, pls check...");
            }
				al=20;
		
		}
	
    if(cipher==ORIGINAL||cipher==PRG||cipher==LRV)
    {
        byte keyex[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
		byte inex[16] = { 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };
		//Expected result:{0x39,0x25,0x84,0x1d,0x02,0xdc,0x09,0xfb,0xdc,0x11,0x85,0x97,0x19,0x6a,0x0b,0x32};

		byte in1[16], in2[16], out1[16], out2[16];
		// In1 and In2 (out and key also) to represent the input to unshared and shared AES block cipher.
		byte key1[16], key2[16];

		for (i = 0; i < 16; i++)
		{
			key1[i] = keyex[i];
			key2[i] = keyex[i];
		}
		
		for (i = 0; i < 16; i++)
		{
			in1[i] = inex[i];
			in2[i] = inex[i];

		}


		for (k = 0; k < 16; k++)
		{
			out1[k] = 0x0;
		}
		
		unsigned int begin1, end1, begin2, end2;
	
		
       //run_aes(in1, out1, key1, nt);

      
	
	//return 0;
		
		//printf("Pre-computation of 160 tables for AES-128\n");
		//gen_t_forall_third(shares, third_order_scheme);
		
		/*******comment which you dont want to use*********/
		
		/***************third order scheme*******************/
		run_aes_shares_third(in2,out2,key2,shares,cipher,nt,time);
    
/*******************corons*******************************/		
		//run_aes_common_share(in2,out2,key2,shares,&subbyte_cs_htable_word_inc,nt,time); 
		
		if (compare_output(out1, out2, 16))
		{
			printf("Successful execution of LUT-based AES\n");
		
		}
		else
		{
			printf("Unsuccessful execution :(, pls check...");
		
		}

    }   
		

	
  
  rand_dein();
	return 0;
}

