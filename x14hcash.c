#include "x14hcash.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sha3/sph_blake.h"
#include "sha3/sph_bmw.h"
#include "sha3/sph_groestl.h"
#include "sha3/sph_jh.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_skein.h"
#include "sha3/sph_luffa.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_shavite.h"
#include "sha3/sph_simd.h"
#include "sha3/sph_echo.h"
#include "sha3/sph_hamsi.h"
#include "sha3/sph_fugue.h"
#include "sha3/sph_shabal.h"
#include "sha3/sph_whirlpool.h"
#include "sph_sm3.h"


void x14hcash_hash(const char* input, char* output, uint32_t len)
{
    sph_blake512_context     ctx_blake;
    sph_bmw512_context       ctx_bmw;
    sph_groestl512_context   ctx_groestl;
    sph_skein512_context     ctx_skein;
    sph_jh512_context        ctx_jh;
    sph_keccak512_context    ctx_keccak;
    sph_luffa512_context    ctx_luffa1;
    sph_cubehash512_context ctx_cubehash1;
    sph_shavite512_context  ctx_shavite1;
    sph_simd512_context     ctx_simd1;
    sph_echo512_context     ctx_echo1;
    sph_hamsi512_context    ctx_hamsi1;
    sph_fugue512_context    ctx_fugue1;
	sm3_ctx_t				 ctx_sm3;

    //these uint512 in the c++ source of the client are backed by an array of uint32
    //uint32_t hashA[16], hashB[16];
	uint512 hash[17];

    sph_blake512_init(&ctx_blake);
    sph_blake512 (&ctx_blake, input, len);
    sph_blake512_close (&ctx_blake, &hash[0]);

    sph_bmw512_init(&ctx_bmw);
    sph_bmw512 (&ctx_bmw, &hash[0], 64);
    sph_bmw512_close(&ctx_bmw, &hash[1]);

    sph_groestl512_init(&ctx_groestl);
    sph_groestl512 (&ctx_groestl, &hash[1], 64);
    sph_groestl512_close(&ctx_groestl, &hash[2]);

    sph_skein512_init(&ctx_skein);
    sph_skein512 (&ctx_skein, &hash[2], 64);
    sph_skein512_close (&ctx_skein, &hash[3]);

    sph_jh512_init(&ctx_jh);
    sph_jh512 (&ctx_jh, &hash[3], 64);
    sph_jh512_close(&ctx_jh, &hash[4]);

    sph_keccak512_init(&ctx_keccak);
    sph_keccak512 (&ctx_keccak, &hash[4], 64);
    sph_keccak512_close(&ctx_keccak, &hash[5]);

    sph_luffa512_init (&ctx_luffa1);
    sph_luffa512 (&ctx_luffa1, &hash[5], 64);
    sph_luffa512_close (&ctx_luffa1, &hash[6]);

    sph_cubehash512_init (&ctx_cubehash1);
    sph_cubehash512 (&ctx_cubehash1, &hash[6], 64);
    sph_cubehash512_close(&ctx_cubehash1, &hash[7]);

    sph_shavite512_init (&ctx_shavite1);
    sph_shavite512 (&ctx_shavite1, &hash[7], 64);
    sph_shavite512_close(&ctx_shavite1, &hash[8]);

    sph_simd512_init (&ctx_simd1);
    sph_simd512 (&ctx_simd1, &hash[8], 64);
    sph_simd512_close(&ctx_simd1, &hash[9]);

    sph_echo512_init (&ctx_echo1);
    sph_echo512 (&ctx_echo1, &hash[9], 64);
    sph_echo512_close(&ctx_echo1, &hash[10]);

	/*增加sm3*/
	//sm3 is 256bit
    sm3_init(&ctx_sm3);
    sph_sm3(&ctx_sm3, &hash[10], 64);
    sph_sm3_close(&ctx_sm3, &hash[11]);

    sph_hamsi512_init (&ctx_hamsi1);
    sph_hamsi512 (&ctx_hamsi1, &hash[11], 64);
    sph_hamsi512_close(&ctx_hamsi1, &hash[12]);

    sph_fugue512_init (&ctx_fugue1);
    sph_fugue512 (&ctx_fugue1, &hash[12], 64);
    sph_fugue512_close(&ctx_fugue1, &hash[13]);



    memcpy(output, hash[13].trim256(), 32);

}
