/*
Ehsan Aerabi 
2019
Curve25519 Key establishment
*/
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define uchar unsigned char // 8-bit byte
#define uint unsigned long // 32-bit word
#define KE_ROTWORD(x) ( ((x) << 8) | ((x) >> 24) )


#define PRINTF_DEBUG 0


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
#define RSA_TEST_BYTES 128 /* 256 bytes * 8 = 2048-bit key length */
#define AES_KEY_SZ 32 /* 32*8 = 256-bit AES KEY */
#define HEAP_HINT NULL
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#define out_size 2048
#define in_size 128
#define HEAP_HINT NULL


int main(void)
{
	    uint32_t err_code;

char errorString[25];
  int ret = -1000;
			byte sharedKey[32];
word32 keySz=32;
 curve25519_key keyPub,keyPrv;
wc_curve25519_init(&keyPub); // initialize key
wc_curve25519_init(&keyPrv); 
RNG rng;
wc_InitRng(&rng); // initialize random number generator
ret= wc_curve25519_make_key(&rng, 32, &keyPub);									


//  This key is assumed as the key sent by the other party.
if(ret != 0) { 
    // making 25519 key
	wc_ErrorString(ret,errorString);
	if(PRINTF_DEBUG)printf("\r\nError maing key: (%d): %s",ret,errorString);
	
}

wc_FreeRng(&rng);
wc_InitRng(&rng); // initialize random number generator


 
////////////////////////////////////////////////////////////////////////////
	if(PRINTF_DEBUG)printf("test");
    while (true)
    {
    // making 25519 key
			ret = wc_curve25519_make_key(&rng, 32, &keyPrv) ;
			if(ret != 0) { 
				wc_ErrorString(ret,errorString);
				if(PRINTF_DEBUG)printf("\r\nError maing key: (%d): %s",ret,errorString);
	
			}

			
			// making 25519 key
			ret = wc_curve25519_shared_secret(&keyPrv, &keyPub, sharedKey, &keySz);
			if(ret != 0) { 
				wc_ErrorString(ret,errorString);
				if(PRINTF_DEBUG)printf("\r\nError maing key: (%d): %s",ret,errorString);
	
			}
			else{
			if(PRINTF_DEBUG)printf("\r\n\r\nKey (%d): ",ret);		
			for(int i=0; i<keySz; i++){if(PRINTF_DEBUG)printf("%x",sharedKey[i]);}
			}

			LEDS_INVERT(1<<leds_list[1]);			
			//////////////////////////////////////////////////////////////////////////



    }
}


