#include <bits/stdc++.h>
#include <time.h>
#include <unistd.h>
#include <chrono>
#include <random>
#include <ratio>
#include "./ModifiedCuckooFilter/src/cuckoofilter.h"
#include "vacuum.h"
#include "hashutil.h"

#include <sodium.h> /* g++ opition: -lsodium */ 
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/time.h>
#include <sys/resource.h>

#include <oqs/oqs.h>

#define MESSAGE (const unsigned char *) "test"
#define MESSAGE_LEN 50

int n = 1000000; /* number of inserted keys --> the size of Dv */
int q = 10000000; /* number of queries */ 
int slots = 8; /* slots per backets */
int max_kick = 400; /* max kick steps */

/* Cleaning up memory etc */
void cleanup_stack(uint8_t *secret_key, size_t secret_key_len);

void cleanup_heap(uint8_t *public_key, uint8_t *secret_key,
                  uint8_t *message, uint8_t *signature,
                  OQS_SIG *sig);

using namespace std;

/* generate n 64-bit random numbers */
void random_gen(int n, vector<uint64_t>& store, mt19937& rd) {
    store.resize(n);
    for (int i = 0; i < n; i++)
        store[i] = (uint64_t(rd()) << 32) + rd();
}

/* generate n 64-bit random numbers */
void random_gen_1(int n, uint64_t** store, mt19937& rd) {
    *store = new uint64_t[n + 128];
    for (int i = 0; i < n; i++)
        (*store)[i] = (uint64_t(rd()) << 32) + rd();
}


/* This function gives an example of the signing operations
 * using only compile-time macros and allocating variables
 * statically on the stack, calling a specific algorithm's functions
 * directly.
 *
 * The macros OQS_SIG_dilithium_2_length_* and the functions OQS_SIG_dilithium_2_*
 * are only defined if the algorithm dilithium_2 was enabled at compile-time
 * which must be checked using the OQS_ENABLE_SIG_dilithium_2 macro.
 *
 * <oqs/oqsconfig.h>, which is included in <oqs/oqs.h>, contains macros
 * indicating which algorithms were enabled when this instance of liboqs
 * was compiled.
 */
static OQS_STATUS example_stack(void) {
    #ifdef OQS_ENABLE_SIG_dilithium_2

	OQS_STATUS rc;

	uint8_t public_key[OQS_SIG_dilithium_2_length_public_key];
	uint8_t secret_key[OQS_SIG_dilithium_2_length_secret_key];
	uint8_t message[MESSAGE_LEN];
	uint8_t signature[OQS_SIG_dilithium_2_length_signature];
	size_t message_len = MESSAGE_LEN;
	size_t signature_len;

	// let's create a random test message to sign
	OQS_randombytes(message, message_len);

	rc = OQS_SIG_dilithium_2_keypair(public_key, secret_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_dilithium_2_keypair failed!\n");
		cleanup_stack(secret_key, OQS_SIG_dilithium_2_length_secret_key);
		return OQS_ERROR;
	}
	rc = OQS_SIG_dilithium_2_sign(signature, &signature_len, message, message_len, secret_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_dilithium_2_sign failed!\n");
		cleanup_stack(secret_key, OQS_SIG_dilithium_2_length_secret_key);
		return OQS_ERROR;
	}
	rc = OQS_SIG_dilithium_2_verify(message, message_len, signature, signature_len, public_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_dilithium_2_verify failed!\n");
		cleanup_stack(secret_key, OQS_SIG_dilithium_2_length_secret_key);
		return OQS_ERROR;
	}

	printf("[example_stack] OQS_SIG_dilithium_2 operations completed.\n");
	cleanup_stack(secret_key, OQS_SIG_dilithium_2_length_secret_key);
	return OQS_SUCCESS; // success!

#else

	printf("[example_stack] OQS_SIG_dilithium_2 was not enabled at compile-time.\n");
	return OQS_SUCCESS;

#endif
}


void test_vf_no_padding_dilithium() { /* Vacuum with Dilithium */

    /*
        We implemented VF_no_padding from scratch.
        It supports fingerprint length from 4 to 16 bits, but we recommend to use fingerprint longer than 8 bits.
        This version aims at flexibility, so it is slower than VF_with_padding.
    */
    struct rusage setup_start, setup_end, keygen_start, keygen_end, 
        sign_start, sign_end, vrfy_start, vrfy_end;

/* for debug
    cout << "Testing vacuum filter(no padding)..." << endl;


    cout << "Keys number = " << n << endl;
    cout << "Queries number = " << q << endl;
*/
    mt19937 rd(12821);
    vector<uint64_t> insKey;
    vector<uint64_t> alienKey;
    /*
    random_gen(n, insKey, rd);
    random_gen(q, alienKey, rd);
    */


    /* Cleaning up memory etc */
    void cleanup_stack(uint8_t *secret_key, size_t secret_key_len);

    void cleanup_heap(uint8_t *public_key, uint8_t *secret_key,
                  uint8_t *message, uint8_t *signature,
                  OQS_SIG *sig);

    /* Definition of structures for Dilithium*/
 
    getrusage(RUSAGE_SELF, &setup_start);
	OQS_STATUS rc;

    uint8_t public_key[OQS_SIG_dilithium_2_length_public_key];
    uint8_t secret_key[OQS_SIG_dilithium_2_length_secret_key];
    uint8_t message[MESSAGE_LEN];
    uint8_t signature[OQS_SIG_dilithium_2_length_signature];
    size_t message_len = MESSAGE_LEN;
    size_t signature_len;

    VacuumFilter<uint16_t, 16> vf;

    /* Setup: Generation of Dilithium keys */
 
    OQS_randombytes(message, message_len);
    rc = OQS_SIG_dilithium_2_keypair(public_key, secret_key);

    if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_dilithium_2_keypair failed!\n");
		cleanup_stack(secret_key, OQS_SIG_dilithium_2_length_secret_key);
        printf("break due to error in Setup\n"); 
	}
    getrusage(RUSAGE_SELF, &setup_end);

    /* KeyGen */

    getrusage(RUSAGE_SELF, &keygen_start);

    random_gen(n, insKey, rd); /* unique value for uint64_t as vk_id */
    random_gen(q, alienKey, rd);

    getrusage(RUSAGE_SELF, &keygen_end);

    /* Sign */
    getrusage(RUSAGE_SELF, &sign_start);


    rc = OQS_SIG_dilithium_2_sign(signature, &signature_len, message, message_len, secret_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_dilithium_2_sign failed!\n");
		cleanup_stack(secret_key, OQS_SIG_dilithium_2_length_secret_key);
		printf("break due to error in Sign\n");
	}

    vf.init(n, slots, max_kick); /* vf.init(max_item_numbers, slots per bucket, max_kick_steps) 
        --> Gen of Vacuum */

    for (int i = 0; i < n; i++)
        if (vf.insert(insKey[i]) == false)
            cout << "Insertion fails when inserting " << i << "th key: " << insKey[i] << endl;

    int T = static_cast<int>(vf.get_load_factor()) * 100;
    getrusage(RUSAGE_SELF, &sign_end);
/*
    printf("T: %d\n", T); 
*/    
    /* Verify */

    getrusage(RUSAGE_SELF, &vrfy_start);
	rc = OQS_SIG_dilithium_2_verify(message, message_len, signature, signature_len, public_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_dilithium_2_verify failed!\n");
		cleanup_stack(secret_key, OQS_SIG_dilithium_2_length_secret_key);
		printf("break due to error in Verify\n");
	}


    for (int i = 0; i < n; i++) 
        if (vf.lookup(insKey[i]) == false) { /* checking insKey[i] by Lookup */
        /*
            cout << "False negative happens at " << i << "th key: " << insKey[i] << endl;
            printf("incrrect AMQ!\n");
            break;
        */
        }

    getrusage(RUSAGE_SELF, &vrfy_end);


/*
    printf("Setup (user-time) \n");
    printf("Setup (sys-time) \n");

    printf("KeyGen (user-time) \n");
    printf("KeyGen (sys-time) \n");

    printf("Sign (user-time) \n");
    printf("Sign (sys-time) \n");

    printf("Verify (user-time) \n");
    printf("Verify (sys-time) \n");
*/

/*
    printf("%lf\n",
        (setup_end.ru_utime.tv_sec  - setup_start.ru_utime.tv_sec) +
        (setup_end.ru_utime.tv_usec - setup_start.ru_utime.tv_usec)*1.0E-6
        );
    printf("%lf\n",
        (setup_end.ru_stime.tv_sec  - setup_start.ru_stime.tv_sec) +
        (setup_end.ru_stime.tv_usec - setup_start.ru_stime.tv_usec)*1.0E-6);

    printf("%lf\n",
        (keygen_end.ru_utime.tv_sec  - keygen_start.ru_utime.tv_sec) +
        (keygen_end.ru_utime.tv_usec - keygen_start.ru_utime.tv_usec)*1.0E-6);
    printf("%lf\n",
        (keygen_end.ru_stime.tv_sec  - keygen_start.ru_stime.tv_sec) +
        (keygen_end.ru_stime.tv_usec - keygen_start.ru_stime.tv_usec)*1.0E-6);

    printf("%lf\n",
        (sign_end.ru_utime.tv_sec  - sign_start.ru_utime.tv_sec) +
        (sign_end.ru_utime.tv_usec - sign_start.ru_utime.tv_usec)*1.0E-6);
    printf("%lf\n",
        (sign_end.ru_stime.tv_sec  - sign_start.ru_stime.tv_sec) +
        (sign_end.ru_stime.tv_usec - sign_start.ru_stime.tv_usec)*1.0E-6);
*/

    printf("%lf\n",
        (vrfy_end.ru_utime.tv_sec  - vrfy_start.ru_utime.tv_sec) +
        (vrfy_end.ru_utime.tv_usec - vrfy_start.ru_utime.tv_usec)*1.0E-6);
/*
    printf("%lf\n",
        (vrfy_end.ru_stime.tv_sec  - vrfy_start.ru_stime.tv_sec) +
        (vrfy_end.ru_stime.tv_usec - vrfy_start.ru_stime.tv_usec)*1.0E-6);
*/


    int false_positive_cnt = 0;

    for (int i = 0; i < q; i++)
        if (vf.lookup(alienKey[i]) == true)
            false_positive_cnt++;

/*
    cout << "False positive rate = " << double(false_positive_cnt) / q << endl;
    cout << "Bits per key = " << vf.get_bits_per_item() << endl;
*/
/*
    for (int i = 0; i < n; i++)
        if (vf.del(insKey[i]) == false)
            cout << "Deletion fails when inserting " << i << "th key: " << insKey[i] << endl;
    cout << endl;
*/
}



void test_batch() {

    /*
    We also implemented batching mode for VF.
    Given an array of keys, VF slices the array into multiple batches. Each batch contains 128 keys.
    Then VF performs insertion/deletion/lookup operation for those batches.
    */

    cout << "Testing VF in batching mode..." << endl;

    int n = 100;
    int q = 10000000;
    cout << "Keys number = " << n << endl;
    cout << "Queries number = " << q << endl;

    mt19937 rd(112983);
    uint64_t* insKey;
    uint64_t* alienKey;
    bool* res;
    res = new bool[max(n, q)];

    random_gen_1(n, &insKey, rd);
    random_gen_1(q, &alienKey, rd);

    cuckoofilter::VacuumFilter<size_t, 16> vf(n);

    /* If you want to enable semi-sorting to save memory and allow some loss on throughput, use
     cuckoofilter::VacuumFilter<size_t, 17, cuckoofilter::PackedTable> vf(n); */

    vf.Add_many(insKey, res, n);
    for (int i = 0; i < n; i++)
        if (res[i] == false) {
            cout << "Insertion fails when inserting " << i << "th key: " << insKey[i] << endl;
            break;
        }

    cout << "Load factor = " << vf.LoadFactor() << endl;

    vf.Contain_many(insKey, res, n);
    for (int i = 0; i < n; i++)
        if (res[i] == false) {
            cout << "False negative happens at " << i << "th key: " << insKey[i] << endl;
            break;
        }

    int cnt = 0;
    vf.Contain_many(alienKey, res, q);
    for (int i = 0; i < q; i++) if (res[i] == true) cnt++;

    cout << "False positive rate = " << double(cnt) / q << endl;
    cout << "Bits per key = " << vf.BitsPerItem() << endl;

    vf.Delete_many(insKey, res, n);
    for (int i = 0; i < n; i++)
        if (res[i] == false) {
            cout << "Deletion fails when inserting " << i << "th key: " << insKey[i] << endl;
            break;
        }

    delete insKey;
    delete alienKey;
    delete res;
}


int main() {

    for (int k = 0; k < 5; k ++) {
        /* libsodium
        test_vf_no_padding();
        */
        test_vf_no_padding_dilithium();
    }
    /* 
    test_vf_with_padding();
    test_batch(); 
    */



    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);

    unsigned char signed_message[crypto_sign_BYTES + MESSAGE_LEN];
    unsigned long long signed_message_len;

    crypto_sign(signed_message, &signed_message_len,
            MESSAGE, MESSAGE_LEN, sk);
/*
    printf("%s\n", signed_message);
    printf("%s\n", MESSAGE);
*/

    return 0;
}

void cleanup_stack(uint8_t *secret_key, size_t secret_key_len) {
	OQS_MEM_cleanse(secret_key, secret_key_len);
}

void cleanup_heap(uint8_t *public_key, uint8_t *secret_key,
                  uint8_t *message, uint8_t *signature,
                  OQS_SIG *sig) {
	if (sig != NULL) {
		OQS_MEM_secure_free(secret_key, sig->length_secret_key);
	}
	OQS_MEM_insecure_free(public_key);
	OQS_MEM_insecure_free(message);
	OQS_MEM_insecure_free(signature);
	OQS_SIG_free(sig);
}
