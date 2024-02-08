#pragma once
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
#include <iostream>

#include <sys/time.h>
#include <sys/resource.h>

#include <oqs/oqs.h>

#define MESSAGE (const unsigned char *) "test"
#define MESSAGE_LEN 32
int n = 100; /* number of users */
int j =n/2; /* test index in verification */

using namespace std;

void cleanup_stack(uint8_t *secret_key, size_t secret_key_len);

void cleanup_heap(uint8_t *public_key, uint8_t *secret_key,
                  uint8_t *message, uint8_t *signature,
                  OQS_SIG *sig);

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

/* copy a set of identifiers to a single array, Dv */
static void printDump(const unsigned char *buff, int length, unsigned char *copy)
{
    int i;

    for (i = 0; i < length; i++) {
        copy[i] = buff[i];
        /* printf("%02x", (buff[i] & 0x000000ff)); for debug */
    }
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

void test_vf_no_padding_dilithium() { /* Vacuum from scratch */

    struct rusage setup_start, setup_end, keygen_start, keygen_end, 
        sign_start, sign_end, vrfy_start, vrfy_end;
    /*
        We implemented VF_no_padding from scratch.
        It supports fingerprint length from 4 to 16 bits, but we recommend to use fingerprint longer than 8 bits.
        This version aims at flexibility, so it is slower than VF_with_padding.
    */

    cout << "Testing trivial construction..." << endl;

    /* int n = 100; */ /* number of inserted keys --> the size of Dv */

    cout << "Keys number = " << n << endl;

    mt19937 rd(12821);
    vector<uint64_t> insKey;

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

    /* Setup: Generation of Dilithiug Keys */

    OQS_randombytes(message, message_len);
    rc = OQS_SIG_dilithium_2_keypair(public_key, secret_key);

    if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_dilithium_2_keypair failed!\n");
		cleanup_stack(secret_key, OQS_SIG_dilithium_2_length_secret_key);
        printf("break due to error in Setup\n"); 
	}
    getrusage(RUSAGE_SELF, &setup_end);

    /* Generation of Libsoudium 
    getrusage(RUSAGE_SELF, &setup_start);

    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);

    unsigned char signed_message[crypto_sign_BYTES + MESSAGE_LEN];
    unsigned long long signed_message_len;

    getrusage(RUSAGE_SELF, &setup_end);
    */


    /* KeyGen: Just Preset */
    /*
    random_gen(n, insKey, rd); 
    random_gen(q, alienKey, rd);
    */
    getrusage(RUSAGE_SELF, &keygen_start);
    /* here is the output of measurement */
    getrusage(RUSAGE_SELF, &keygen_end);


    /* Sign */ 

    getrusage(RUSAGE_SELF, &sign_start);
    random_gen(n, insKey, rd); /* Define Dv */

    rc = OQS_SIG_dilithium_2_sign(signature, &signature_len, message, message_len, secret_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_dilithium_2_sign failed!\n");
		cleanup_stack(secret_key, OQS_SIG_dilithium_2_length_secret_key);
		printf("break due to error in Sign\n");
	}

    /* Signing of libsodium
    unsigned char hash[crypto_generichash_BYTES];
    crypto_generichash(hash, sizeof hash, MESSAGE, MESSAGE_LEN, NULL, 0);
    std::cout << "debug after hash\n" << endl;


    std::cout << "debug before sign\n" << endl;
    crypto_sign(signed_message, &signed_message_len, MESSAGE, MESSAGE_LEN, sk);
    std::cout << "debug after sign\n" << endl;
    */




    int T = static_cast<int>(vf.get_load_factor()) * 100;
    getrusage(RUSAGE_SELF, &sign_end);
    printf("T: %d\n", T); /* for debug */




    /* Verify */


    getrusage(RUSAGE_SELF, &vrfy_start);
    unsigned char unsigned_message[MESSAGE_LEN];
    unsigned long long unsigned_message_len;

    for (int i = 0; i < n; i++)
        if (insKey[i] == insKey[j])
            cout << j <<"th key is correct" << endl;

    rc = OQS_SIG_dilithium_2_verify(message, message_len, signature, signature_len, public_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_dilithium_2_verify failed!\n");
		cleanup_stack(secret_key, OQS_SIG_dilithium_2_length_secret_key);
		printf("break due to error in Verify\n");
	}


    /* Verification of libsodium
    if (crypto_sign_open(unsigned_message, &unsigned_message_len, signed_message, 
        signed_message_len, pk) != 0) { 
        printf("incorrect signature!\n");
    }
    */


    /* cout << "debug before lookup\n" << endl; */

    getrusage(RUSAGE_SELF, &vrfy_end);
    printf("Setup (user-time) \n");
    printf("Setup (sys-time) \n");

    printf("KeyGen (user-time) \n");
    printf("KeyGen (sys-time) \n");

    printf("Sign (user-time) \n");
    printf("Sign (sys-time) \n");

    printf("Verify (user-time) \n");
    printf("Verify (sys-time) \n");


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

    printf("%lf\n",
        (vrfy_end.ru_utime.tv_sec  - vrfy_start.ru_utime.tv_sec) +
        (vrfy_end.ru_utime.tv_usec - vrfy_start.ru_utime.tv_usec)*1.0E-6);
    printf("%lf\n",
        (vrfy_end.ru_stime.tv_sec  - vrfy_start.ru_stime.tv_sec) +
        (vrfy_end.ru_stime.tv_usec - vrfy_start.ru_stime.tv_usec)*1.0E-6);

    cout << endl;
}


void test_vf_no_padding() { /* Vacuum from scratch */

    struct rusage setup_start, setup_end, keygen_start, keygen_end, 
        sign_start, sign_end, vrfy_start, vrfy_end;
    /*
        We implemented VF_no_padding from scratch.
        It supports fingerprint length from 4 to 16 bits, but we recommend to use fingerprint longer than 8 bits.
        This version aims at flexibility, so it is slower than VF_with_padding.
    */

    cout << "Testing trivial construction..." << endl;

    /* int n = 100; */ /* number of inserted keys --> the size of Dv */

    cout << "Keys number = " << n << endl;

    mt19937 rd(12821);
    vector<uint64_t> insKey;

    /*
    random_gen(n, insKey, rd);
    random_gen(q, alienKey, rd);
    */

    VacuumFilter<uint16_t, 16> vf;

    /* Setup: Generation of Crypto keys */
    getrusage(RUSAGE_SELF, &setup_start);

    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);

    unsigned char signed_message[crypto_sign_BYTES + MESSAGE_LEN];
    unsigned long long signed_message_len;

    getrusage(RUSAGE_SELF, &setup_end);



    /* KeyGen */
    /*
    random_gen(n, insKey, rd); 
    random_gen(q, alienKey, rd);
    */
    getrusage(RUSAGE_SELF, &keygen_start);
    /* here is the output of measurement */
    getrusage(RUSAGE_SELF, &keygen_end);


    /* Sign */ 

    getrusage(RUSAGE_SELF, &sign_start);
    random_gen(n, insKey, rd); /* Define Dv */
 
    unsigned char hash[crypto_generichash_BYTES];
    /*
    unsigned char value[sizeof(insKey)];
    */
    /* 
    std::cout << "debug before sizeof\n" << endl;
    */
    /* hash-and-sign paradigm for Signing on m||Dv */

    /* 
    for (int i=0; i <n; i++ ){
        std::memcpy(value,&insKey[i],sizeof(insKey[i]));
    }
    */ 
    
    /*     std::cout << "debug before hash\n" << endl; */
    /* original hash function 
    crypto_generichash(hash, sizeof hash, MESSAGE, MESSAGE_LEN, NULL, 0);
    */
    crypto_generichash(hash, sizeof hash, MESSAGE, MESSAGE_LEN, NULL, 0);
    std::cout << "debug after hash\n" << endl;
    /* delete[] value;    */

    std::cout << "debug before sign\n" << endl;
    crypto_sign(signed_message, &signed_message_len, MESSAGE, MESSAGE_LEN, sk);
    std::cout << "debug after sign\n" << endl;


    /* printDump(const unsigned char *buff, int length, unsigned char *copy) */

    /* original sign function
    crypto_sign(signed_message, &signed_message_len, MESSAGE, MESSAGE_LEN, sk);
    std::cout << "cout: " << hash << endl;
    printf("hash output::: %s::%s\n", print_hex(hash, sizeof hash), MESSAGE);

    */


    int T = static_cast<int>(vf.get_load_factor()) * 100;
    getrusage(RUSAGE_SELF, &sign_end);
    printf("T: %d\n", T); /* for debug */




    /* Verify */


    getrusage(RUSAGE_SELF, &vrfy_start);
    unsigned char unsigned_message[MESSAGE_LEN];
    unsigned long long unsigned_message_len;

    for (int i = 0; i < n; i++)
        if (insKey[i] == insKey[j])
            cout << j <<"th key is correct" << endl;


    /* cout << "debug before crypto_sign_open\n" << endl; */
    if (crypto_sign_open(unsigned_message, &unsigned_message_len, signed_message, 
        signed_message_len, pk) != 0) { /* checking signature verification */
        printf("incorrect signature!\n");
        /* incorrect signature! */
    }


    /* cout << "debug before lookup\n" << endl; */

    getrusage(RUSAGE_SELF, &vrfy_end);
    printf("Setup (user-time) \n");
    printf("Setup (sys-time) \n");

    printf("KeyGen (user-time) \n");
    printf("KeyGen (sys-time) \n");

    printf("Sign (user-time) \n");
    printf("Sign (sys-time) \n");

    printf("Verify (user-time) \n");
    printf("Verify (sys-time) \n");


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

    printf("%lf\n",
        (vrfy_end.ru_utime.tv_sec  - vrfy_start.ru_utime.tv_sec) +
        (vrfy_end.ru_utime.tv_usec - vrfy_start.ru_utime.tv_usec)*1.0E-6);
    printf("%lf\n",
        (vrfy_end.ru_stime.tv_sec  - vrfy_start.ru_stime.tv_sec) +
        (vrfy_end.ru_stime.tv_usec - vrfy_start.ru_stime.tv_usec)*1.0E-6);

    cout << endl;
}


int main() {

    for (int k =0; k < 5; k++) {
        test_vf_no_padding_dilithium();
    }


/*
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);

    unsigned char signed_message[crypto_sign_BYTES + MESSAGE_LEN];
    unsigned long long signed_message_len;

    crypto_sign(signed_message, &signed_message_len,
            MESSAGE, MESSAGE_LEN, sk);

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