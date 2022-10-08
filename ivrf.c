/* ****************************** *
 * Implemented by Raymond K. ZHAO *
 *                                *
 * iVRF (XMSS variant)            *
 * ****************************** */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/sha.h>

#include <time.h>

#include "xmss_core.h"
#include "drbg_rng.h"

#include "cpucycles.h"

#include "randombytes.h"
#include "utils.h"

#define LOGN 18
#define N (1 << LOGN)
#define T 100
#define LAMBDA 16
#define DRBG_SEED_LENGTH 48
#define XMSS_SEED_LENGTH 96

#define HASH_LENGTH (2 * LAMBDA)
#define MU_LENGTH (2 * LAMBDA)

#define XMSS_OID 0x00000016
#define XMSS_PK_SIZE 64
#define XMSS_SK_SIZE 997
#define XMSS_SIG_SIZE 2404

#define BENCHMARK_ITERATION 1000

static long long keygen_xmss_cycle, eval_xmss_keygen_cycle, eval_xmss_sign_cycle, verify_xmss_cycle;

typedef struct 
{
	unsigned char hash[HASH_LENGTH];
} TREE_NODE;

static xmss_params params;

void keygen(TREE_NODE *tree, AES256_CTR_DRBG_struct *s, AES256_CTR_DRBG_struct *s_prime)
{
	unsigned char buf[HASH_LENGTH + XMSS_PK_SIZE];	
	uint32_t i, j;
	unsigned char seed_s[DRBG_SEED_LENGTH], seed_s_prime[DRBG_SEED_LENGTH];
	AES256_CTR_DRBG_struct s_i, s_prime_i;
	unsigned char r_i[XMSS_SEED_LENGTH];
	
	unsigned char pk_i[XMSS_PK_SIZE], sk_i[XMSS_SK_SIZE];
	
	long long cycle1, cycle2; 
		
	/* s, s_prime <-- G.Key(1^{\lambda}) */
	randombytes(seed_s, DRBG_SEED_LENGTH);
	randombytes(seed_s_prime, DRBG_SEED_LENGTH);

	drbg_randombytes_init(&s_i, seed_s, NULL, LAMBDA);
	memcpy(s, &s_i, sizeof(s_i));
	drbg_randombytes_init(&s_prime_i, seed_s_prime, NULL, LAMBDA);
	memcpy(s_prime, &s_prime_i, sizeof(s_prime_i));
	
	for (i = 0; i < N; i++)
	{
		/* Derive x_{i,0} by running G.Next on s */
		drbg_randombytes(&s_i, tree[N + i].hash, HASH_LENGTH);

		/* x_{i,j+1} = H(x_{i,j}) */
		for (j = 0; j < T - 1; j++)
		{
			memcpy(buf, tree[N + i].hash, HASH_LENGTH);
			SHA256(buf, HASH_LENGTH, tree[N + i].hash);
		}

		/* Derive r_i by running G.Next on s' */
		drbg_randombytes(&s_prime_i, r_i, XMSS_SEED_LENGTH);
		
		cycle1 = cpucycles();
		/* (pk_i, sk_i) <-- XMSS.KeyGen(r_i) */
		xmss_core_seed_keypair(&params, pk_i, sk_i, r_i);
		
		cycle2 = cpucycles();
		keygen_xmss_cycle += cycle2 - cycle1;
		
		/* x_{i,t}=H(x_{i,t-1},pk_i) */
		memcpy(buf, tree[N + i].hash, HASH_LENGTH);
		memcpy(buf + HASH_LENGTH, pk_i, XMSS_PK_SIZE);
		SHA256(buf, HASH_LENGTH + XMSS_PK_SIZE, tree[N + i].hash);
	}	
	
	/* Merkle tree 
	 * root index = 1
	 * for index i, left child is 2*i, right child is 2*i+1 
	 * for index i, its sibling is i^1, its parent is i>>1 */
	for (i = N; i >= 2; i >>= 1)
	{
		for (j = i >> 1; j < i; j++)
		{
			memcpy(buf, tree[2 * j].hash, HASH_LENGTH);
			memcpy(buf + HASH_LENGTH, tree[2 * j + 1].hash, HASH_LENGTH);
			SHA256(buf, 2 * HASH_LENGTH, tree[j].hash);
		}
	}
}

void keyupd(AES256_CTR_DRBG_struct *s, AES256_CTR_DRBG_struct *s_prime)
{
	unsigned char buf[XMSS_SEED_LENGTH];
	
	/* (s, s') <-- (G.Next(s), G.Next(s')) */
	drbg_randombytes(s, buf, HASH_LENGTH);
	drbg_randombytes(s_prime, buf, XMSS_SEED_LENGTH);
}

void eval(unsigned char *v, unsigned char *y, TREE_NODE *ap, unsigned char *pk, unsigned char *sig, const unsigned char *mu1, const unsigned char *mu2, const uint32_t i_in, const uint32_t j_in, const AES256_CTR_DRBG_struct *s, const AES256_CTR_DRBG_struct *s_prime, const TREE_NODE *tree)
{
	unsigned char buf[HASH_LENGTH + MU_LENGTH];	
	uint32_t i, j;
	AES256_CTR_DRBG_struct s_in, s_prime_in;
	unsigned char r[XMSS_SEED_LENGTH];
	
	unsigned char sk[XMSS_SK_SIZE];
	
	long long cycle1, cycle2, cycle3;

	unsigned char sig_attach[XMSS_SIG_SIZE + MU_LENGTH];
	unsigned long long sig_len; 
	
	/* Parse sk_av=(s_i, x_{i,0}, s_i', r_i) */
	memcpy(&s_in, s, sizeof(s_in));
	drbg_randombytes(&s_in, y, HASH_LENGTH);
	memcpy(&s_prime_in, s_prime, sizeof(s_prime_in));
	drbg_randombytes(&s_prime_in, r, XMSS_SEED_LENGTH);
	
	/* y = H^{t-1-j}(x_{i,0}) */
	for (j = 0; j < T - 1 - j_in; j++)
	{
		memcpy(buf, y, HASH_LENGTH);
		SHA256(buf, HASH_LENGTH, y);
	}
	
	/* v = H(y,\mu1) */
	memcpy(buf, y, HASH_LENGTH);
	memcpy(buf + HASH_LENGTH, mu1, MU_LENGTH);
	SHA256(buf, HASH_LENGTH + MU_LENGTH, v);
	
	cycle1 = cpucycles();
	/* pk <-- XMSS.KeyGen(r_i) */
	xmss_core_seed_keypair(&params, pk, sk, r);
	
	cycle2 = cpucycles();
    /* Update the index in the secret key. */
    xmss_sk_update(&params, sk, j_in);

	/* sig <-- XMSS.Sign(sk, \mu_2) */
	xmss_core_sign(&params, sk, sig_attach, &sig_len, mu2, MU_LENGTH);
	
	cycle3 = cpucycles();
	
	/* Detach sig and mu2 */
	memcpy(sig, sig_attach, XMSS_SIG_SIZE);
	
	eval_xmss_keygen_cycle = cycle2 - cycle1;
	eval_xmss_sign_cycle = cycle3 - cycle2;
	
	/* copy the hash values of siblings along the path to the root for i-th leaf (index is N+i) */
	j = 0;
	for (i = N + i_in; i > 1; i >>= 1)
	{
		memcpy(ap[j++].hash, tree[i ^ 1].hash, HASH_LENGTH);
	}
}

uint32_t verify(const unsigned char *mu1, const unsigned char *mu2, const uint32_t i_in, const uint32_t j_in, const unsigned char *v, const unsigned char *y, const TREE_NODE *ap, const unsigned char *pk, const unsigned char *sig, const TREE_NODE *root)
{
	unsigned char buf[HASH_LENGTH + XMSS_PK_SIZE];	
	uint32_t i, j, i_cur;
	unsigned char v_new[HASH_LENGTH];
	unsigned char root_new[HASH_LENGTH];
	int xmss_verify_res;
	
	long long cycle1, cycle2;
	
	unsigned char sig_attach[XMSS_SIG_SIZE + MU_LENGTH];
	unsigned char mu2_open[XMSS_SIG_SIZE + MU_LENGTH];
	unsigned long long mu2_open_len;
	
	/* H(y,\mu1)*/
	memcpy(buf, y, HASH_LENGTH);
	memcpy(buf + HASH_LENGTH, mu1, MU_LENGTH);
	SHA256(buf, HASH_LENGTH + MU_LENGTH, v_new);
	
	/* if v != H(y,\mu1), return 0 */
	for (i = 0; i < HASH_LENGTH; i++)
	{
		if (v_new[i] != v[i])
		{
			return 0;
		}
	}
	
	/* Attach mu2 to sig */
	memcpy(sig_attach, sig, XMSS_SIG_SIZE);
	memcpy(sig_attach + XMSS_SIG_SIZE, mu2, MU_LENGTH);
	
	cycle1 = cpucycles();
	/* XMSS.Verify(pk, sig, \mu2) */
	xmss_verify_res = xmss_core_sign_open(&params, mu2_open, &mu2_open_len, sig_attach, XMSS_SIG_SIZE + MU_LENGTH, pk);
	
	cycle2 = cpucycles();
	verify_xmss_cycle = cycle2 - cycle1;
	
	if (xmss_verify_res)
	{
		return 0;
	}
	
	/* y'=H^{j}(y) */
	memcpy(root_new, y, HASH_LENGTH);
	for (j = 0; j < j_in; j++)
	{
		memcpy(buf, root_new, HASH_LENGTH);
		SHA256(buf, HASH_LENGTH, root_new);
	}
	
	/* x_i=H(y',pk) */
	memcpy(buf, root_new, HASH_LENGTH);
	memcpy(buf + HASH_LENGTH, pk, XMSS_PK_SIZE);
	SHA256(buf, HASH_LENGTH + XMSS_PK_SIZE, root_new);
	
	/* compute root' by using x_{i}, index i_in, and AP */
	i_cur = i_in;
	for (i = 0; i < LOGN; i++)
	{
		/* if i-th LSB of i_in is 1, then for i-th node on the path to the root, its parent has hash value H(AP || x), where x is the hash value of this node and AP is some hash value from the AuthPath i.e. this node's sibling */  
		if (i_cur & 1)
		{
			memcpy(buf, ap[i].hash, HASH_LENGTH);
			memcpy(buf + HASH_LENGTH, root_new, HASH_LENGTH);
		}
		/* otherwise, this node's parent has hash value H(x || AP) */
		else
		{
			memcpy(buf, root_new, HASH_LENGTH);
			memcpy(buf + HASH_LENGTH, ap[i].hash, HASH_LENGTH);
		}
		SHA256(buf, 2 * HASH_LENGTH, root_new);
		
		i_cur >>= 1;
	}
	
	/* if root' != pk_av, return 0 */
	for (i = 0; i < HASH_LENGTH; i++)
	{
		if (root_new[i] != root->hash[i])
		{
			return 0;
		}
	}
	
	return 1;
}

int main()
{
	static TREE_NODE tree[2 * N];
	AES256_CTR_DRBG_struct s_orig, s_prime_orig, s, s_prime;
	uint32_t i;
	uint32_t i_in, j_in;
	unsigned char v[HASH_LENGTH], y[HASH_LENGTH];
	TREE_NODE ap[LOGN];
	unsigned char mu1[MU_LENGTH], mu2[MU_LENGTH];
	
	unsigned char pk[XMSS_PK_SIZE], sig[XMSS_SIG_SIZE];
	
	long long cycle1, cycle2, cycle3, cycle4, cycle5;
	
	uint32_t verify_res;
	
	uint32_t benchmark_iteration; 
	
	/* XMSS parameters */
	xmss_parse_oid(&params, XMSS_OID);

	memset(tree, 0, sizeof(tree));
	
	cycle1 = cpucycles();
	keygen(tree, &s_orig, &s_prime_orig);
	cycle2 = cpucycles();
	
	printf("%lld,%lld\n", cycle2 - cycle1, keygen_xmss_cycle);
	
	srand(time(NULL));
	
	/* j = 0 */
	for (benchmark_iteration = 0; benchmark_iteration < BENCHMARK_ITERATION; benchmark_iteration++)
	{
		memcpy(&s, &s_orig, sizeof(s));
		memcpy(&s_prime, &s_prime_orig, sizeof(s_prime));
		
		randombytes(mu1, MU_LENGTH);
		randombytes(mu2, MU_LENGTH);
		
		i_in = rand() % N;
		j_in = 0;
		
		for (i = 0; i < i_in; i++)
		{
			keyupd(&s, &s_prime);
		}
		
		cycle3 = cpucycles();
		eval(v, y, ap, pk, sig, mu1, mu2, i_in, j_in, &s, &s_prime, tree);
		cycle4 = cpucycles();
		verify_res = verify(mu1, mu2, i_in, j_in, v, y, ap, pk, sig, tree + 1);
		cycle5 = cpucycles();
		
		printf("%lld,%lld,%lld,%lld,%lld,%u\n", cycle4 - cycle3, eval_xmss_keygen_cycle, eval_xmss_sign_cycle, cycle5 - cycle4, verify_xmss_cycle, verify_res);
	}
	
	/* j = t - 1 */
	for (benchmark_iteration = 0; benchmark_iteration < BENCHMARK_ITERATION; benchmark_iteration++)
	{
		memcpy(&s, &s_orig, sizeof(s));
		memcpy(&s_prime, &s_prime_orig, sizeof(s_prime));
		
		randombytes(mu1, MU_LENGTH);
		randombytes(mu2, MU_LENGTH);
		
		i_in = rand() % N;
		j_in = T - 1;
		
		for (i = 0; i < i_in; i++)
		{
			keyupd(&s, &s_prime);
		}
		
		cycle3 = cpucycles();
		eval(v, y, ap, pk, sig, mu1, mu2, i_in, j_in, &s, &s_prime, tree);
		cycle4 = cpucycles();
		verify_res = verify(mu1, mu2, i_in, j_in, v, y, ap, pk, sig, tree + 1);
		cycle5 = cpucycles();
		
		printf("%lld,%lld,%lld,%lld,%lld,%u\n", cycle4 - cycle3, eval_xmss_keygen_cycle, eval_xmss_sign_cycle, cycle5 - cycle4, verify_xmss_cycle, verify_res);
	}

	return 0;
}
