#include <stdio.h>
#include <openssl/sha.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

#include <openssl/hmac.h>
#include <openssl/opensslconf.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/aes.h>


#include <sys/time.h>
#include <sys/resource.h>


int N=100; /* Num. of devices */
int User = 50; /* Num. of users in List */
int sec_lev = 32;

const char *command = {"Command Message"}; /* command for Auth*/
const char *command_ver = {"Command Message"}; /* command for Vrfy */
 

static void printDump(const unsigned char *buff, int length, unsigned char *copy)
{
    int i;

    for (i = 0; i < length; i++) {
        copy[i] = buff[i];
        /* for debug
        printf("%02x", (buff[i] & 0x000000ff));
        */
    }
}

static void printCipher(const unsigned char *buff)
{
    int i;

    for (i = 0; i < sizeof(buff); i++) {
        printf("%02x", (buff[i] & 0x000000ff));
    }
}

/*
static void printDump(const unsigned char *buff, int length)
{
    int i;

    for (i = 0; i < length; i++) {
        printf("%02x", (buff[i] & 0x000000ff));
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
        else {
            printf(" ");
        }
    }
    printf("\n\n");
}
*/



/* definition of device info. */
struct device_info {
    unsigned char id[32];        /*  device name */
    unsigned char name0[33];
    unsigned char name1[33];
    char keyy[EVP_MAX_MD_SIZE]; /* key y_id */
    char keyr[EVP_MAX_MD_SIZE]; /* key r_id */
    char keyk[EVP_MAX_MD_SIZE]; /* key K_id */
};

/* definition of auth info. */
struct command_info {
    unsigned char id[32];        /*  device name */
    char gamma[EVP_MAX_MD_SIZE]; /* auth token gamma */
    char tau[EVP_MAX_MD_SIZE]; /* auth token tau */
};

/* generation of random seed */
int GetRandom(int min, int max)
{
	return min + (int)(rand()*(max-min+1.0)/(1.0+RAND_MAX));
}

/* generatio of random strings, e.g., device name */
char* rand_text(int length, char result[32]) {
    int i, index;
    const char char_set[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
 
    for (i = 0; i < length; i++) {
        index = GetRandom(0,strlen(char_set) - 1);
        result[i] = char_set[index];
    }
    return result;
}

/* generation of temporal key */
char* key_gen(char result[32]) {
    int i, index;
    const char char_set[] = "0123456789abcdef";
 
    for (i = 0; i < sec_lev; i++) {
        index = GetRandom(0,strlen(char_set) - 1);
        result[i] = char_set[index];
    }
    return result;
}

/* concatenation of device name||0 */
char* name_gen0(char* s1, const char* s2)
{
    int i;
    for(i=0 ; i < s2[i] != '\0'; i++)
    {
        s1[i] = s2[i];
    }
    s1[i] = '0';
    s1[i+1] = s2[i];
    return s1;
}

/* concatenation of device name||1 */
char* name_gen1(char* s1, const char* s2)
{
    int i;
    for(i=0 ; i < s2[i] != '\0'; i++)
    {
        s1[i] = s2[i];
    }
    s1[i] = '1';
    s1[i+1] = s2[i];
    return s1;
}

/* concatenation of counter */
char* counter(char* s1, const char* s2, int ctr_in)
{
    int i, j;
    int len = strlen(s2);
    char s[16];

    ctr_in = ctr_in +1;
    snprintf(s, 16, "%x", ctr_in);


    for(i=0 ; s2[i] != '\0'; i++)
    {
        s1[i] = s2[i];
    }

    for(j=0 ; j < 16; j++)
    {
        s1[i] = s[j];
        i++;
    }

    s1[i+1] = s2[i];
    return s1;
}

/* check strings for verification*/
int check_strings(const char* s1, const char* s2)
{
    int i, s1_len, s2_len;
    s1_len = strlen(s1);
    s2_len = strlen(s2);

    if (s1_len != s2_len) return 0;

/*    printf("strings 1\n"); // for debug */
    for(i=0 ; i < s1_len; i++)
    {
        if (s1[i] != s2[i]) return 0;
    }
/*    printf("strings 2\n"); // for debug */
    return 1;
}

/*
char* init(char* s1)
{
    int i;
    for(i=0 ; i != strlen(s1); i++)
    {
        s1[i] = '\0';
    }
    return s1;
}
*/

/* generatio of random numbers as string */
char* rand_num_string(int length, char result[16]) {
    int i, index;
    const char char_set[] = "0123456789ABCDEF";
 
    for (i = 0; i < length; i++) {
        index = GetRandom(0,strlen(char_set) - 1);
        result[i] = char_set[index];
    }
    return result;
}

/* Generation of Random Numbers via AES */
unsigned int Random(const int i)
{
    EVP_CIPHER_CTX *en; 
    en = EVP_CIPHER_CTX_new();

    const char key[]   = "13f75ae483d03c233"; 

    int length = 16;
    int c_len, j;
    char string[16];
    char dest[16];


    rand_num_string(length, string);
    /*
    for (j = 0; j < sizeof(string); j++) {
        printf("%c", string[j]);
    } for debug
    printf("\n");
    */

    EVP_EncryptInit_ex(en, EVP_aes_128_ecb(), NULL, (unsigned char*)key, NULL);

    EVP_EncryptUpdate(en, dest, &c_len, string, sizeof(string));
    /* printCipher(dest); for debug */

    /* unsigned int ran_num = (unsigned int)dest;*/
    unsigned int ran_num = atoi(dest);
    /* printf("debug for ran_num from AES: %d\n", ran_num); */
    ran_num = ran_num % i;
    /* printf("debug for ran_num for i: %d\n", ran_num); */
    /* EVP_EncryptFinal_ex(&en, (unsigned char *)(dest + c_len), &f_len); */

    /*  PrintBytes(dest, destlen); */

    EVP_CIPHER_CTX_cleanup(en);

    return ran_num;
}

void swap(char* s1, char* s2) {
    int i;
    char c;
    for(i = 0; i < EVP_MAX_MD_SIZE; i++) {
        c = s1[i]; 
        s1[i] = s2[i]; 
        s2[i] = c; 
    }
}


/* swap command info from d1 to d2 */
void struct_swap(struct command_info *c1, struct command_info *c2) {
    struct command_info temp;
    
    temp = *c2;
    *c2 = *c1;
    *c1 = temp;
}

/* prime number testing */
int check_prime(int number) {
    int divisor = sqrtf( (double) number)+1;
    while (divisor > 1) {
        /* for debug
        printf("divisor: %d\n", divisor);
        */
        if ( (number % divisor) == 0) {
            return 0;
        }
        divisor--;
    }

    return 1;
} 

/*
unsigned char* Encrypt(const char* key, const char* data, const size_t datalen, const unsigned char* iv, unsigned char* dest, const size_t destlen)
{
    EVP_CIPHER_CTX en;
    int i, f_len=0;
    int c_len = destlen;


    memset(dest, 0x00, destlen);


    EVP_CIPHER_CTX_init(&en);
    EVP_EncryptInit_ex(&en, EVP_aes_128_cbc(), NULL, (unsigned char*)key, iv);


    EVP_EncryptUpdate(&en, dest, &c_len, (unsigned char *)data, datalen);
    //EVP_EncryptFinal_ex(&en, (unsigned char *)(dest + c_len), &f_len);


    printf("c_len: %d\n", c_len);
    printf("f_len: %d\n", f_len);
    PrintBytes(dest, destlen);


    EVP_CIPHER_CTX_cleanup(&en);


    return dest;
}
*/

int main(int argc, char *argv[])
{
    char *message = {"Sample Message"};
    unsigned char digest[SHA256_DIGEST_LENGTH];
    int i, j; 

    struct rusage setup_start, setup_end, join_start, join_end, 
        auth_start, auth_end, vrfy_start, vrfy_end;

/* setup */

    getrusage(RUSAGE_SELF, &setup_start);
    /* master key = hmac key */
	char    key[]   = "93f75ae483d03c23358fa5330ff4a3f5"; 
    size_t  keylen  = strlen (key);
    int ctr = 0;

    SHA256_CTX sha_ctx;
    SHA256_Init(&sha_ctx); /* initialize ctx of sha*/
    SHA256_Update(&sha_ctx, message, sizeof(message)); /* input message */
    SHA256_Final(digest, &sha_ctx); /* output as digest */

    getrusage(RUSAGE_SELF, &setup_end);

    /* for debug 
    printf("%s\n", message);

    for (int i = 0; i < sizeof(digest); ++i) {
        printf("%x", digest[i]);
    }
    printf("\n");
    */


/* Join: process of HMAC */

    /* Define device_info and pointers for copy */
    struct device_info dev[N];

    /* initialization of device info. */

    for (i=0; i < N; i++){

        for (j=0; j < 32; j++){
            dev[i].id[j] = '\0';
        }
        for (j=0; j<33; j++){
            dev[i].name0[j] = '\0';
            dev[i].name1[j] = '\0';
        }
        for (j=0; j < EVP_MAX_MD_SIZE; j++){
            dev[i].keyy[j] = '\0';
            dev[i].keyr[j] = '\0';
            dev[i].keyk[j] = '\0';
        }
    }

        

    const char data[] = "abcdefghijklmnopqrstuvwxyz";
	unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int data_len, out_len = EVP_MAX_MD_SIZE;
    int name_len = 10; /* Device name length is here */

    getrusage(RUSAGE_SELF, &join_start);

    for (i = 0; i < N; i++){

    /* Generation of device name */
        rand_text(name_len, dev[i].id);
        /* for debug
        printf("device name  %d:", i);
        for (j = 0; j < strlen(dev[i].id); j++) {
            printf("%c", dev[i].id[j]);
        }
        printf("\n");
        */


        /*
        printf("device name  %d:", i);
        for (j = 0; j < strlen(dev[i].id); j++) {
            printf("%x", dev[i].id[j]);
        }
        printf("\n");
    */


    /* copy from dev[i] to dev[i]||0*/
        name_gen0(dev[i].name0, dev[i].id);

        /* for debug
        printf("device name||0  %d:", i);
        for (j = 0; j < sizeof(dev[i].name0); j++) {
            printf("%c", dev[i].name0[j]);
        }
        printf("\n");
        */
        /*
        printf("device name||0  %d:", i);
        for (j = 0; j < sizeof(dev[i].name0); j++) {
            printf("%x", dev[i].name0[j]);
        }
        printf("\n");
    */



    /* copy from dev[i] to dev[i]||1*/
        name_gen1(dev[i].name1, dev[i].id);
        
        /* for debug
        printf("device name||1  %d:", i);
        for (j = 0; j < sizeof(dev[i].name1); j++) {
            printf("%c", dev[i].name1[j]);
        }
        printf("\n");
        */

        /*
        printf("device name||1  %d:", i);
        for (j = 0; j < sizeof(dev[i].name1); j++) {
            printf("%x", dev[i].name1[j]);
        }
        printf("\n");
    */

    /* Generation of key r_id */
        data_len = strlen(dev[i].name0);
        keylen  = strlen (key);
        HMAC(EVP_sha256(), key, keylen, dev[i].name0, data_len, out, &out_len);
        printDump(out, out_len, dev[i].keyr);
        /*    HMAC(EVP_sha256(), key, keylen, data, data_len, out, &out_len);*/
        /* for debug
        printf("key rid c:\n");
        printDump(out, out_len, dev[i].keyr);
        printf("\n");
        */
        /*
        printf("key rid x:\n");
        for (j = 0; j < sizeof(out); j++) {
            printf("%x", out[i]);
            dev[i].keyr[j] = out[j];
        }
        printf("\n");
    */


    /* Generation of key K_id */
        data_len = strlen(dev[i].keyr);
        HMAC(EVP_sha256(), key, keylen, dev[i].keyr, data_len, out, &out_len);
        printDump(out, out_len, dev[i].keyk);
        /* for debug
        printf("key Kid c:\n");
        printDump(out, out_len, dev[i].keyk);
        printf("\n");
        */

    /*        
        printf("key Kid x:\n");
        for (j = 0; j < sizeof(out); j++) {
            printf("%x", out[i]);
            dev[i].keyk[j] = out[j];
        }
        printf("\n");
    */

        
    /* Generation of key y_id */
        data_len = strlen(dev[i].name1);
        HMAC(EVP_sha256(), key, keylen, dev[i].name1, data_len, out, &out_len);
        printDump(out, out_len, dev[i].keyy);
        /* for debug
        printf("key yid c:\n");
        printDump(out, out_len, dev[i].keyy);
        */
    /*
        printf("key yid x:\n");
        for (j = 0; j < sizeof(out); j++) {
            printf("%x", out[i]);
            dev[i].keyy[j] = out[j];
        }
        printf("\n");
    */

        /* printf("\n\n");  */

    }

    getrusage(RUSAGE_SELF, &join_end);


/* Auth: process of HMAC */

    /* Define cmd output from Auth*/
    struct command_info cmd[N];
    unsigned char cmd_tmp[sec_lev];

    int temp[User]; /* temp variable for sort */
    int temp_rand, check; /* variable for sort*/

    for (i=0; i < N; i++){
        for (j = 0; j < sec_lev; j++){
            cmd[i].id[j] = '\0';
        }
        for (j =0; j < EVP_MAX_MD_SIZE; j++){
            cmd[i].gamma[j] = '\0';
            cmd[i].tau[j] = '\0';
        }
    }

    for (j =0; j < EVP_MAX_MD_SIZE; j++){
        temp[j] = '\0';
    }

    for (j=0; j < sec_lev; j++){
        cmd_tmp[j]  = '\0';
    }
    /* for debug
    printf("Command for Auth: %s\n", command);
    */

    getrusage(RUSAGE_SELF, &auth_start);


    /* temporal key \bar{k} */
    char key_temp[EVP_MAX_MD_SIZE]; 
    for (j=0; j < EVP_MAX_MD_SIZE; j++){
            key_temp[j] = '\0';
    }

    key_gen(key_temp);
    keylen = strlen (key_temp);

    for (j=0; j< N; j++){
        data_len = strlen(dev[j].keyy);
        HMAC(EVP_sha256(), key_temp, keylen, dev[j].keyy, data_len, out, &out_len);
        printDump(out, out_len, cmd[j].gamma);
        /* for debug
        printf("%d: Gamma for %s:\n", j, dev[j].id);
        printDump(out, out_len, cmd[j].gamma);
        printf("\n");        
        */

        if (j < User) {
            name_gen1(cmd_tmp, command);
            /* for debug             printf("%s\n", cmd_tmp); */
            counter(cmd_tmp, cmd_tmp, ctr);
            /* for debug             printf("%s\n", cmd_tmp); */

            data_len= strlen(cmd_tmp);
            keylen = strlen(dev[j].keyk);

            HMAC(EVP_sha256(), dev[j].keyk, keylen, cmd_tmp, data_len, out, &out_len);
            printDump(out, out_len, cmd[j].tau);
            /* for debug
            printf("%d: Tau for %s in List:\n", j, dev[j].id);
            printf("\n");        
            */
        } 
        /* 
        printf("\n");        
        */
    }

    /* prime number testing */
    int user_prime = User; 
    while (check_prime(user_prime) == 0) {
        user_prime++;
    }
    /* for debug
    printf("User Prime: %d\n", user_prime);
    */

    for (j=0; j< User; j++){
        LOOP:; /* loop point */
        check = 0;
        
        temp_rand = Random(user_prime);

        /* printf("\ntemp: %d\n", temp_rand); */
        for (i=0; i<j; i++) {
            if (temp[i] == temp_rand) {
                check = 1;
            }
        }
        if (check == 1){
            /* printf("Device %d: %d\n", j, temp_rand); */ /* for debug */
            goto LOOP; /* goto LOOP for the retry*/
        }

        if ( temp_rand >= User) goto LOOP;
        temp[j] = temp_rand;

        struct_swap (&cmd[temp_rand], &cmd[j]);
        /* for debug
        printf("device %d: --> %d (success)\n", j, temp_rand);
        */
    }


    
    getrusage(RUSAGE_SELF, &auth_end);



/* Verify: process of HMAC */

    unsigned char gamma_temp[EVP_MAX_MD_SIZE];
    unsigned char tau_temp[EVP_MAX_MD_SIZE];
    int ver_result[N];
    unsigned char ver_temp[sec_lev];
    int ctr_ver = 0;

    for (j=0; j < sec_lev; j++){
            ver_temp[j] = '\0';
    }

    for (j=0; j < EVP_MAX_MD_SIZE; j++){
        gamma_temp[j] = '\0';
        tau_temp[j] = '\0';
    }



    getrusage(RUSAGE_SELF, &vrfy_start);

    

    for (j=0; j< N; j++){
        name_gen1(ver_temp, command_ver);
        /* for debug         printf("%s\n", ver_temp); */
        counter(ver_temp, ver_temp, ctr_ver);

        /* for debug printf("%s\n", ver_temp); */

        keylen = strlen(key_temp);
        data_len= strlen(dev[j].keyy);
        

        HMAC(EVP_sha256(), key_temp, keylen, dev[j].keyy, data_len, out, &out_len);
        printDump(out, out_len, gamma_temp);
        /*
        HMAC(EVP_sha256(), key_temp, keylen, dev[j].keyy, data_len, out, &out_len);
        */
        /* for debug
        printf("%d: Verification of Gamma for %s:\n", j, dev[j].id);
        printf("\n");
        */

        for (i=0; i< User; i++) {
            if (check_strings(gamma_temp, cmd[i].gamma) == 1){
                break;
            }
        }

        /* for debug 
        printf("position of device %d: %d\n", j, i);
        */

        if (check_strings(gamma_temp, cmd[i].gamma) == 0 ) {
            /* for debug 
            printf("verify check 1\n");
            */
            ver_result[j] = 0;
        } else {
            keylen = strlen(dev[j].keyk);

            data_len = strlen(ver_temp);

            HMAC(EVP_sha256(), dev[j].keyk, keylen, ver_temp, data_len, out, &out_len);
            /* 
            printDump(out, out_len, tau_temp);
            printf("\n"); 
            */
            if ( check_strings(tau_temp, cmd[i].tau) == 1) {
                /* for debug
                printf("verify check 2\n");
                */
                ver_result[j] = 1;
            } else {
                ver_result[j] = 0;
            }
        }
        /* for debug
        printf("Device %d: Result %d\n\n", j, ver_result[j]);
        */

    }

    getrusage(RUSAGE_SELF, &vrfy_end);





    /* for debug
    for (int i = 0; i < sizeof(digest); ++i) {
        printf("%x", digest[i]);
    }
    printf("\n");




    printf("hmac_sha256 output:\n");
    for (int i = 0; i < sizeof(out); ++i) {
        printf("%x", out[i]);
    }
    printf("\n");
    */


    /* Measurement Output */
    printf("Command for Auth: %s\n", command);
    printf("Num. of devices: %d\n", N);
    printf("Num. of devices in List: %d\n", User);
    printf("Num. of devices not in List: %d\n", N-User);

    /* 
    printf("Setup (user-time) \t%lfs\n",
        (setup_end.ru_utime.tv_sec  - setup_start.ru_utime.tv_sec) +
        (setup_end.ru_utime.tv_usec - setup_start.ru_utime.tv_usec)*1.0E-6);
    printf("Setup (sys-time) \t%lfs\n",
        (setup_end.ru_stime.tv_sec  - setup_start.ru_stime.tv_sec) +
        (setup_end.ru_stime.tv_usec - setup_start.ru_stime.tv_usec)*1.0E-6);

    printf("Join (user-time) \t%lfs\n",
        (join_end.ru_utime.tv_sec  - join_start.ru_utime.tv_sec) +
        (join_end.ru_utime.tv_usec - join_start.ru_utime.tv_usec)*1.0E-6);
    printf("Join (sys-time) \t%lfs\n",
        (join_end.ru_stime.tv_sec  - join_start.ru_stime.tv_sec) +
        (join_end.ru_stime.tv_usec - join_start.ru_stime.tv_usec)*1.0E-6);

    printf("Auth (user-time) \t%lfs\n",
        (auth_end.ru_utime.tv_sec  - auth_start.ru_utime.tv_sec) +
        (auth_end.ru_utime.tv_usec - auth_start.ru_utime.tv_usec)*1.0E-6);
    printf("Auth (sys-time) \t%lfs\n",
        (auth_end.ru_stime.tv_sec  - auth_start.ru_stime.tv_sec) +
        (auth_end.ru_stime.tv_usec - auth_start.ru_stime.tv_usec)*1.0E-6);
    */
    printf("Verify (user-time) \t%lfs\n",
        (vrfy_end.ru_utime.tv_sec  - vrfy_start.ru_utime.tv_sec) +
        (vrfy_end.ru_utime.tv_usec - vrfy_start.ru_utime.tv_usec)*1.0E-6);
    /* 
    printf("Verify (sys-time) \t%lfs\n",
        (vrfy_end.ru_stime.tv_sec  - vrfy_start.ru_stime.tv_sec) +
        (vrfy_end.ru_stime.tv_usec - vrfy_start.ru_stime.tv_usec)*1.0E-6);
    */

    

    return 0;
}
