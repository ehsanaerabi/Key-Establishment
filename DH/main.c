/*
Ehsan Aerabi
DH key establishment
2019
*/

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#define PRINTF_DEBUG 0



#define uchar unsigned char // 8-bit byte
#define uint unsigned long // 32-bit word
#define KE_ROTWORD(x) ( ((x) << 8) | ((x) >> 24) )



//#include "RSAkeys.h"
/* certs_test.h contains der formatted key buffer rsa_key_der_2048 */
#define USE_CERT_BUFFERS_1024
#ifdef USE_CERT_BUFFERS_1024
#include <wolfssl/certs_test.h>
#else
    #error "Please define USE_CERT_BUFFERS_2048 when building wolfSSL!"
#endif


void check_ret(int val, char* fail)
{
    if (val < 0) {
        if(PRINTF_DEBUG)printf("%s Failed with error %d\n", fail, val);
      //  exit(-99);
    }
    return;
}
#define RSA_TEST_BYTES 256 /* 256 bytes * 8 = 2048-bit key length */
#define AES_KEY_SZ 32 /* 32*8 = 256-bit AES KEY */
#define HEAP_HINT NULL
#include <wolfssl/wolfcrypt/dh.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#define out_size 2048
#define in_size 128
#define HEAP_HINT NULL


int main(void)
{
	
	    uint32_t err_code;
	char errorString[80];
DhKey keyB;	////// Side B key	///
byte privB[256];
byte pubB[256];	
word32 privSzB, pubSzB;
const unsigned char* tmpB = dh_key_der_1024;
	word32 idxB = 0;

	/////////////////////
	
	/////// Side A key ///////////////
DhKey key;
int ret;
const byte* p= dh_p; // initialize with prime };
const  byte* g= dh_g; // initialize with base };
word32 pASz = sizeof(dh_p);
word32 gASz = sizeof(dh_g);
byte priv[256];
byte pub[256];
byte agree[256];
word32 agreeSz;
word32 privSz, pubSz;
wc_InitDhKey(&key); // initialize key
WC_RNG rng;
wc_InitRng(&rng); // initialize rng
// Set DH parameters using wc_DhSetKey or wc_DhKeyDecode


////////////Side B calculations ///////////
	wc_InitDhKey(&keyB); // initialize key
//	ret = wc_DhKeyDecode(tmpB, &idxB, &keyB, sizeof_client_keypub_der_1024);
	//wc_ErrorString(ret,errorString);
//	if(PRINTF_DEBUG)printf("\r\nKeyDecode B Error: (%d): %s",ret,errorString);
	ret = wc_DhSetKey(&keyB, p, pASz, g, gASz);
	if(ret != 0) { 
		wc_ErrorString(ret,errorString);
		if(PRINTF_DEBUG)printf("\r\nwc_DhSetKey Error: (%d): %s",ret,errorString);
	}
	ret = wc_DhGenerateKeyPair(&keyB, &rng, privB, &privSzB, pubB, &pubSzB);
	wc_ErrorString(ret,errorString);
	if(PRINTF_DEBUG)printf("\r\nGenerate B Error: (%d): %s",ret,errorString);
		nrf_delay_ms(10);
	/////////////////////////////////
	wc_FreeRng(&rng);
	wc_InitRng(&rng); // initialize random number generator



		////////////////////////////////////////////////////////////////////////////
	if(PRINTF_DEBUG)printf("test");
    while (true)
    {
			wc_InitDhKey(&key); // initialize key

			ret = wc_DhSetKey(&key, p, pASz, g, gASz);
			if(ret != 0) { 
				wc_ErrorString(ret,errorString);
				if(PRINTF_DEBUG)printf("\r\nwc_DhSetKey Error: (%d): %s",ret,errorString);
	
			}			

			ret = wc_DhGenerateKeyPair(&key, &rng, priv, &privSz, pub, &pubSz);
			if(ret != 0) { 
				wc_ErrorString(ret,errorString);
				if(PRINTF_DEBUG)printf("\r\nwc_DhGenerateKeyPair Error: (%d): %s",ret,errorString);
	
			}
		

			ret = wc_DhAgree(&key,agree, &agreeSz, priv, sizeof(priv), pubB, pubSzB);
			if(ret != 0) { 
				wc_ErrorString(ret,errorString);
				if(PRINTF_DEBUG)printf("\r\nwc_DhAgree Error: (%d): %s",ret,errorString);
	
			}			else{
			if(PRINTF_DEBUG)printf("\r\n\r\nKey (%d): ",ret);		
			for(int i=0; i<agreeSz; i++){if(PRINTF_DEBUG)printf("%x",agree[i]);}
			}


	
			//////////////////////////////////////////////////////////////////////////



    }
}


/** @} */
