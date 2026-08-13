/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"

#endif

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"
#define KEY_SIZE 13


typedef struct adpcrypt_tmp
{
  u8 digest_buf[11];
  u32 testvar[1];

} adpcrypt_tmp_t;





DECLSPEC void initial_state(int s[])
{

  #ifdef _unroll
  #pragma unroll
  #endif
    for(int i=0;i<256;i++){
    s[i] = i;
    }
}




DECLSPEC void swap ( int *a,  int *b)
{
  
  
  int tmp;

     tmp = *a;
    *a = *b;
    *b = tmp;	
}








KERNEL_FQ void m90000_init (KERN_ATTR_TMPS (adpcrypt_tmp_t))
{
  /**
   * base
   */

const u64 gid = get_global_id (0);
	if (gid >= gid_max) return;
	


const u32 pw_len = pws[gid].pw_len;
//const u32 salt_len = salt_bufs[SALT_POS].salt_len;





  /**
   * init
   */


int key[256];  						//key buffer
int out[256];						//
int S[256]; 						//define the S array
//int i;
int j;
j = 0;

u32 key_buf0[2];   					//key dec buffer
u32 salt_buf0[2];  					//salt dec buffer

u8 q1 = 0;							//for the round of keystream
u8 q2 = 0;
int out_ks_arr[277]; 






initial_state(S); 					//Fill the S Array
key_buf0[0] = pws[gid].i[ 0];		//Fill key_buf0 with password guess
key_buf0[1] = pws[gid].i[ 1];	
salt_buf0[0] = salt_bufs[SALT_POS].salt_buf[ 0];	//Fill salt_buf0 with user provided salt
salt_buf0[1] = salt_bufs[SALT_POS].salt_buf[ 1];


  





  /**
   * prepare
   */

   
//printf("%i\n", pw_len); //prints password length
//printf("%lli\n",pws[gid]);  //Prints passwords
//printf("%llu\n",salt_bufs[SALT_POS]);  //prints salt LE
	
	
	
	
	key[0] = key_buf0[0] >> 0 & 0xFF; //Build key array by converting key decimal num to two char dec num
	key[1] = key_buf0[0] >> 8 & 0xFF; 
	key[2] = key_buf0[0] >> 16 & 0xFF; 
	key[3] = key_buf0[0] >> 24 & 0xFF; 
	key[4] = key_buf0[1] >> 0 & 0xFF; 

	key[5] = salt_buf0[0] >> 0 & 0xFF; //Build key array by converting salt decimal num to two char dec num
    key[6] = salt_buf0[0] >> 8 & 0xFF; 
	key[7] = salt_buf0[0] >> 16 & 0xFF; 
    key[8] = salt_buf0[0] >> 24 & 0xFF; 
	key[9] = salt_buf0[1] >> 0 & 0xFF; 
    key[10] = salt_buf0[1] >> 8 & 0xFF; 
	key[11] = salt_buf0[1] >> 16 & 0xFF; 
    key[12] = salt_buf0[1] >> 24 & 0xFF; 
	
	
	





//printf("%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u\n", key[0],key[1],key[2],key[3],key[4],key[5],key[6],key[7],key[8],key[9],key[10],key[11],key[12]);





  
   for(int a=0;a<256;a++){
    j = (j + S[a] + key[a % KEY_SIZE]) % 256;  //Make initial keystream
		
    swap(&S[a], &S[j]);	

	}
	






    for(int z=0;z<277;z++){  //iterate to discard 256 bytes and make enough keystream to reach the end of VC1 in LDU1

        q1 = (q1 + 1)%256;
        q2 = (q2 + S[q1])%256;
        swap(&S[q1], &S[q2]);
        out_ks_arr[z] = S[(S[q1]+S[q2])%256];



    }









//   for(int t=0;t<277;t++){   		//print keystream in hex prefixed with 0
//   printf("%01x,", out_ks_arr[t]);   
//   }




//   for(int t=267;t<277;t++){   		//print keystream in hex at position of VC1 in LDU1
//   printf("%x,", out_ks_arr[t]);   
//   }  







	tmps[gid].digest_buf[0] = out_ks_arr[267];
	tmps[gid].digest_buf[1] = out_ks_arr[268];
	tmps[gid].digest_buf[2] = out_ks_arr[269];
	tmps[gid].digest_buf[3] = out_ks_arr[270];
	tmps[gid].digest_buf[4] = out_ks_arr[271];
	tmps[gid].digest_buf[5] = out_ks_arr[272];
	tmps[gid].digest_buf[6] = out_ks_arr[273];
	tmps[gid].digest_buf[7] = out_ks_arr[274];



	

	

	//printf("%x,", tmps[gid].digest_buf[0]);   //To test what's in the tmps buffer
	



	






}


KERNEL_FQ void m90000_loop (KERN_ATTR_TMPS (adpcrypt_tmp_t))
{
  /**
   * base
   */


  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * init
   */
  
  







  /**
   * digest
   */



  /**
   * loop
   */

  
  }




KERNEL_FQ void m90000_comp (KERN_ATTR_TMPS (adpcrypt_tmp_t))
{
  /**
   * modifier
   */

  #define il_pos 0
  
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const u64 lid = get_local_id (0);
  
    

int buffer_r0;
int buffer_r1;



  /**
   * digest
   */

//printf("%x,", tmps[gid].digest_buf[0]);   //Prints what's in the digest buffer




	buffer_r0 = tmps[gid].digest_buf[0] | tmps[gid].digest_buf[1] << 8 | tmps[gid].digest_buf[2] << 16 | tmps[gid].digest_buf[3] << 24 ;
	buffer_r1 = tmps[gid].digest_buf[4] | tmps[gid].digest_buf[5] << 8 | tmps[gid].digest_buf[6] << 16 | tmps[gid].digest_buf[7] << 24 ;




//printf("%u,", buffer_r0);   //Prints the dec buffer

//printf("%u,", buffer_r1);   //Prints the dec buffer








  
//  const u32 r0 = 447435183;    //IT WORKS!!! Hashcat expects Big Endian
//  const u32 r1 = 323678193;
//  const u32 r2 = 0;
//  const u32 r3 = 0;


  
  const u32 r0 = buffer_r0;
  const u32 r1 = buffer_r1;
  const u32 r2 = 0;
  const u32 r3 = 0;




  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
