#include <stdio.h>
#include <string.h>
#include <trace.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#include <ConfidentialPackageSpecification_t.h>
#include "cpm_config.h"
#include "cpm_crypto.h"
#include "ta_secstor.h"
#include "cpm.h"

int enc_main(void);

const char supportedOperations[][48] = {
    "ecall_ping",
    "ecall_is_operation_supported",
    "ecall_get_device_public_key_data_size",
    "ecall_export_device_public_key",
    "ecall_install_application_key",
    "ecall_begin_application_deployment",
    "ecall_initialize_decryption_aes_gcm",
    "ecall_add_application_data",
    "ecall_verify_application_sha256_rsa_pkcs1_v15",
    "ecall_end_application_deployment",
};

mbedtls_ctr_drbg_context m_ctr_drbg_contex;
mbedtls_entropy_context m_entropy_context;
mbedtls_pk_context m_pk_context;
bool initialized = false;

unsigned char public_key[MAX_PUB_KEY_SIZE]; 
int public_key_size = 0;

/* TODO, linked list or something to support mulitple applications and different key sizes/protocols 
   For now we assure AES256 GCM, and fail on anything else
   */
char todo_application_id[64];
unsigned char todo_application_key[32+1];


unsigned char todo_iv[12];
unsigned char todo_tag[16];
unsigned char calculated_tag[16];

int 
ecall_ping(unsigned int* supported_contract_version) 
{
    int ret;
    
    cpm_log("ecall_ping");
    
    //TODO, FIX THIS to actually start at TA load time..
    if (!initialized) {
        enc_main();
    }

    *supported_contract_version = ( (CPS_VERSION_MAJOR << 16) | CPS_VERSION_MINOR);
    return 0;
}

int 
ecall_is_operation_supported(char* operation_name, bool* is_supported)
{
    int i;
    int nof_operations;
            
    *is_supported = false;
    nof_operations = (sizeof(supportedOperations) / sizeof(supportedOperations[0]));
    
    for (i = 0; i < nof_operations; i++) {
        if (strcmp(supportedOperations[i], operation_name) == 0) {
            *is_supported = true;
            break;
        }
    }
    return 0;
}

int 
ecall_get_device_public_key_data_size(unsigned int* data_size)
{    
    *data_size = public_key_size;
    return 0; 
}

int 
ecall_export_device_public_key( unsigned char* data, unsigned int data_size)
{
    int ret = 0;
    mbedtls_mpi E;
            
    /* Make sure we are initialized and ready for operation */
    if (!initialized) {
        return -1;
    }
    
    /* Check if the Host has given us enough space to store the public key */
    if (data_size < public_key_size) 
    {
        return -2;
    }
    
    memcpy(data, public_key, public_key_size); 
    return 0; 
}

int 
ecall_install_application_key(
    char* application_id,
    unsigned char* data,
    unsigned int data_size)
{
    size_t olen = 0;
    int ret;    
        
    memcpy(todo_application_id, application_id, strnlen(application_id, sizeof(todo_application_id)));
    todo_application_id[sizeof(todo_application_id)-1] = '\0';
    
    
    cpm_log("ecall_install_application_key(%i)", data_size);
    
    ret = mbedtls_pk_decrypt( 
        &m_pk_context,                  /* The PK context to use. It must have been set up with a private key.  */
        data,                           /* Input to decrypt */
        data_size,                      /* Input size */
        todo_application_key,           /* Decrypted output */
        &olen,                          /* Decrypted message length */
        sizeof(todo_application_key),   /* Size of the output buffer */
        mbedtls_ctr_drbg_random,        /* RNG function */
        &m_ctr_drbg_contex );           /* RNG parameter */
    
    if (ret == 0 && olen == sizeof(todo_application_key) ) {
        cpm_log("Loaded application key");
        // All went well, but nothing to do with the key at this point.
    }
    
    if( ret != 0) {
        cpm_log("Application key unwrap error (%x)", ret);
    }
    
    if (olen != (sizeof(todo_application_key)-1)) {
        cpm_log("Application key size mismatch (%i)", olen);
        return -1;
    }
    
    return 0;
}

int 
ecall_begin_application_deployment(
    char* application_id,
    unsigned long int total_data_size) 
{
    int ret;
    
    cpm_log("ecall_begin_application_deployment");
    
    //TODO, FIX THIS to actually start at TA load time..
    if (!initialized) {
        enc_main();
    }
    
    return 0; 
}

int 
ecall_initialize_decryption_aes_gcm(
    char* application_id,
    unsigned int key_strength,
    unsigned char* iv,
    unsigned int iv_size,
    unsigned char* tag,
    unsigned int tag_size)
{
    
    if (key_strength != 256){
        return -1;
    }
    
    if (iv_size != 12) {
        return -2;
    }
    
    if (tag_size != 16) {
        return -3;
    }
    
    memcpy(todo_iv, iv ,12);
    memcpy(todo_tag, tag ,16);
    
    return cpm_crypto_init(todo_application_key, todo_iv); 
};

int
ecall_add_application_data(
    char* application_id,
    unsigned char* data,
    unsigned int data_size)
{
    int ret;
    
    cpm_log("ecall_add_application_data (%i)", data_size);
    
    ret = cpm_crypto_update(data, data_size); 
    
    return ret;
}

int 
ecall_verify_application_sha256_rsa_pkcs1_v15(
    char* application_id,
    unsigned int key_strength,
    unsigned char* digest,
    unsigned int digest_size,
    unsigned char* signature,
    unsigned int signature_size,
    unsigned char* public_key,
    unsigned int public_key_size,
    bool* digest_match,
    bool* signature_match) 
{
    int ret = 0;

    *digest_match = false;
    *signature_match = false;

    ret = memcmp(calculated_tag, todo_tag, 16);
    if (ret == 0) {
        *digest_match = true;
    }

    //*signature_match = true;
    return 0; 
}

int 
ecall_end_application_deployment(char* application_id)
{
    int ret = 0;
    unsigned char* buffer;
    int buffer_size;
    int i;

    cpm_log("ecall_end_application_deployment");

    ret = cpm_crypto_finish(calculated_tag, 16 );
    if( ret != 0) {
        cpm_log("cpm_crypto_finish error (%x)", ret);
        return -1;
    }
    
    ret = memcmp(calculated_tag, todo_tag, 16);
    if( ret != 0) {
        cpm_log("TAG mismatch");
        return -2;
    }
    
    ret = cpm_crypto_get_buffer(&buffer, &buffer_size);
    if( ret != 0) {
        cpm_log("Error getting plain text data");
        return -3;
    }

    cpm_log("Installing application with size %i", buffer_size);
    
    ret = secstor_install_ta(buffer, buffer_size);
    if (ret != 0) {
        cpm_log("Error installing application" );
        return -4;
    }
            
    return 0; 
}

/* Assemble UUID from constants generated from EDL file */
#define TA_UUID							\
{ 								\
	CPM_UUID_P0, CPM_UUID_P1, CPM_UUID_P2,			\
	{							\
		CPM_UUID_P3, CPM_UUID_P4, CPM_UUID_P5, CPM_UUID_P6, CPM_UUID_P7, CPM_UUID_P8, CPM_UUID_P9, CPM_UUID_P10 \
	}							\
}


OE_SET_ENCLAVE_OPTEE(
    TA_UUID,                        /* UUID */
    2 * 1024 * 1024,                /* Heap size, in bytes */
        512 * 1024,                 /* Stack size, in bytes */
    (                               /* Flags */
        ( TA_FLAG_SINGLE_INSTANCE | 
	  TA_FLAG_INSTANCE_KEEP_ALIVE |
	  TA_FLAG_MULTI_SESSION )
    ),
    "0.0.1",                        /* Version */
    "ConfidentialPackageManager")   /* Description */

int enc_main(void)
{
    int ret = 0;
    uint8_t *pos;

    cpm_log("Starting ConfidentialPackageManager Instance configuration");
    
    mbedtls_ctr_drbg_init(&m_ctr_drbg_contex);
    mbedtls_entropy_init(&m_entropy_context);
    mbedtls_pk_init(&m_pk_context);

    // Initialize entropy.
    ret = mbedtls_ctr_drbg_seed(
        &m_ctr_drbg_contex,
        mbedtls_entropy_func,
        &m_entropy_context,
        NULL,
        0);
    if (ret != 0)
    {
        cpm_log("mbedtls_ctr_drbg_seed failed.");
        goto error_ctr_drbg_seed;
    }

    // Initialize RSA context.
    ret = mbedtls_pk_setup(&m_pk_context, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    if (ret != 0)
    {
        cpm_log("mbedtls_pk_setup failed.");
        goto error_pk_setup;
    }
    
    /* For now we regenerate our key after reboot/reload of TA
     * Generate an ephemeral 2048-bit RSA key pair with exponent 65537 for the enclave. */
    ret = mbedtls_rsa_gen_key(
        mbedtls_pk_rsa(m_pk_context),
        mbedtls_ctr_drbg_random,
        &m_ctr_drbg_contex,
        2048,
        65537);
    if (ret != 0)
    {
        cpm_log("mbedtls_rsa_gen_key failed\n");
        goto error_keygen;
    }
   
    pos = public_key + sizeof(public_key);
    public_key_size = mbedtls_pk_write_pubkey(
        &pos,                   /* Reference to the current position pointer */	
        public_key,             /* Start of the buffer */
        &m_pk_context);         /* The PK context to use. It must have been set up with a private key */
    
    if (public_key_size) {
        memmove(public_key, (public_key + sizeof(public_key) - public_key_size), public_key_size);
        memset(public_key + public_key_size, 0, (sizeof(public_key) - public_key_size));
        ret = 0;
    }
    else{
        ret = -1;
        goto error_pub_key_export;
    }
    
    initialized = true;
    
    return ret;

error_pub_key_export:    
error_keygen:
error_pk_setup:
error_ctr_drbg_seed:
    mbedtls_ctr_drbg_free(&m_ctr_drbg_contex);
    
    return ret;
}

int cpm_log(const char* format, ...)
{
    va_list args;

    char ocall_log_buffer[128];
    int ocall_log_res;

    va_start(args, format);
    vsnprintf(ocall_log_buffer, sizeof(ocall_log_buffer), format, args );
    va_end(args);

    ocall_log(&ocall_log_res, ocall_log_buffer);
}


