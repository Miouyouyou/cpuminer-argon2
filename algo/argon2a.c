#include "miner.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sha3/ar2/src/argon2.h"
#include "sha3/ar2/src/cores.h"
#include "sha3/sj/scrypt-jane.h"

#define T_COSTS 2
#define M_COSTS 16
#define MASK 8
#define ZERO 0

void argon_call(void *out, void *in, void *salt, int type) {
  argon2_context context;

  context.out = (uint8_t *)out;
  context.pwd = (uint8_t *)in;
  context.salt = (uint8_t *)salt;

  /*context.outlen = context.pwdlen = context.saltlen = (uint32_t)32;
  context.secret = NULL;
  context.secretlen = 0;
  context.ad = NULL;
  context.adlen = 0;
  context.t_cost = T_COSTS;
  context.m_cost = M_COSTS;
  context.lanes = 1;
  context.threads = 1;
  context.allocate_cbk = NULL;
  context.free_cbk = NULL;
  context.flags = ARGON2_DEFAULT_FLAGS;*/

  argon2_core(&context, type);
}

void argon2hash(void *output, const void *input)
{
	// these uint512 in the c++ source of the client are backed by an array of uint32
	uint32_t _ALIGN(32) hashA[8], hashB[8], hashC[8];

	my_scrypt((const unsigned char *)input, 80,
		(const unsigned char *)input, 80,
		(unsigned char *)hashA);

  argon_call(hashB, hashA, hashA, (hashA[0] & MASK) == ZERO);

	my_scrypt((const unsigned char *)hashB, 32,
		(const unsigned char *)hashB, 32,
		(unsigned char *)hashC);

	memcpy(output, hashC, 32);
}

void print32_8(const char *name, uint32_t const *array) {
  printf("%s = {%u, %u, %u, %u, %u, %u, %u, %u}\n",
          name, array[0], array[1], array[2], array[3],
          array[4], array[5], array[6], array[7]);
  fflush(stdout);
}

void print32_20(uint32_t const *array) {
  printf("endiandata = {%u, %u, %u, %u, %u, %u, %u, %u, %u, %u, \n"
         "              %u, %u, %u, %u, %u, %u, %u, %u, %u, %u};\n",
         array[0], array[1], array[2], array[3], array[4], array[5],
         array[6], array[7], array[8], array[9], array[10], array[11],
         array[12], array[13], array[14], array[15], array[16], array[17],
         array[18], array[19]);
  fflush(stdout);
}

/*
endiandata = {112, 229073008, 2948850784, 3439580603, 1611532206, 1012975376, 498386606, 2312676211, 7, 130840290, 
              2325134540, 2444873763, 4181173308, 903589205, 1437875342, 243513206, 2190807, 1452926722, 487889154, 3439853568};
hash = {1075678136, 2273663754, 3679060, 62416301, 203416509, 1563502333, 3468862456, 1074760924}
hash = {1599186965, 1230876208, 1309998516, 2993379400, 3636837378, 3899913743, 494409547, 2990165571}
ptarget = {0, 0, 0, 0, 0, 0, 0, 2097120}

endiandata = {112, 229073008, 2948850784, 3439580603, 1611532206, 1012975376, 498386606, 2312676211, 7, 130840290, 
              2325134540, 2444873763, 4181173308, 903589205, 1437875342, 243513206, 2190807, 1452926722, 487889154, 3322413056};
hash = {75052469, 4070530951, 3981219640, 3160869629, 2321597451, 3552628764, 1665867528, 515283464}
hash = {942124899, 857428725, 3672137193, 2418483151, 2721542355, 2707062344, 1575641614, 1028486680}
ptarget = {0, 0, 0, 0, 0, 0, 0, 2097120}

endiandata = {112, 229073008, 2948850784, 3439580603, 1611532206, 1012975376, 498386606, 2312676211, 7, 130840290, 
              2325134540, 2444873763, 4181173308, 903589205, 1437875342, 243513206, 2190807, 1452926722, 487889154, 3288858624};
hash = {3626601866, 41682822, 310109646, 1966118925, 2105680071, 831454619, 3603935876, 125797734}
hash = {456588711, 858260234, 3387955895, 228706512, 1976537114, 3767076379, 1485303672, 388454513}
ptarget = {0, 0, 0, 0, 0, 0, 0, 2097120}

*/

int scanhash_argon2(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce,	uint64_t *hashes_done)
{
	uint32_t _ALIGN(64) endiandata[20];
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;

	for (int k=0; k < 20; k++)
		be32enc(&endiandata[k], ((uint32_t*)pdata)[k]);

	do {
		const uint32_t Htarg = ptarget[7];
		uint32_t _ALIGN(32) hash[8];
		be32enc(&endiandata[19], nonce);
   /*print32_20(endiandata);
    print32_8("hash", hash);*/
		argon2hash(hash, endiandata);
    /*print32_8("hash", hash);
    print32_8("ptarget", ptarget);*/
		if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
			pdata[19] = nonce;
			*hashes_done = pdata[19] - first_nonce;
			return 1;
		}
		nonce++;
	} while (nonce < max_nonce && !work_restart[thr_id].restart);

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;
}
