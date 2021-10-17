#include <string.h>
#include <trace.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#include <ConfidentialPackageSpecification_t.h>
#include "cpm_crypto.h"
#include "cpm_config.h"

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
    '\0'
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
unsigned char todo_application_key[256/8];
unsigned char todo_iv[16];
unsigned char todo_tag[16];

int 
ecall_ping(unsigned int* supported_contract_version) 
{
    int ret;
    
    EMSG("ecall_ping");
    ocall_log(&ret, "ecall_ping");
    
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
    
    EMSG("ecall_is_operation_supported");
        
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
    EMSG("ecall_get_device_public_key_data_size");
    
    *data_size = public_key_size;
    return 0; 
}

int 
ecall_export_device_public_key( unsigned char* data, unsigned int data_size)
{
    int ret = 0;
    mbedtls_mpi E;
    
    EMSG("ecall_export_device_public_key");
        
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
    EMSG("ecall_install_application_key");

    /* For now only 1 size supported */
    if (data_size != sizeof( todo_application_key) ) {
        return -1;
    }
    
    memcpy(todo_application_id, application_id, strnlen(application_id, sizeof(todo_application_id)));
    todo_application_id[sizeof(todo_application_id)-1] = '\0';
    
    ret = mbedtls_pk_decrypt( 
        &m_pk_context,                  /* The PK context to use. It must have been set up with a private key.  */
        data,                           /* Input to decrypt */
        data_size,                      /* Input size  */
        todo_application_key,           /* Decrypted output */
        &olen,                          /* Decrypted message length */
        sizeof(todo_application_key),   /* Size of the output buffer */
        mbedtls_ctr_drbg_random,        /* RNG function */
        &m_ctr_drbg_contex );           /* RNG parameter */
    
    if (ret == 0 && olen == sizeof(todo_application_key) ) {
        // Don't do anything on purpose
    }

    return 0;
}

int 
ecall_begin_application_deployment(
    char* application_id,
    unsigned long int total_data_size) 
{
    
    EMSG("ecall_begin_application_deployment");
        
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
    EMSG("ecall_initialize_decryption_aes_gcm");
    
    if (key_strength != 256){
        return -1;
    }
    
    if (iv_size != 12) {
        return -2;
    }
    
    if (tag_size != 16) {
        return -3;
    }
    
    memcpy(todo_iv, iv ,16);
    memcpy(todo_tag, tag ,16);
    
    return = cpm_crypto_init(todo_application_key, todo_iv); 
};

int 
ecall_add_application_data(
    char* application_id,
    unsigned char* data,
    unsigned int data_size)
{
    EMSG("ecall_add_application_data");
    
    return cpm_crypto_update(data, data_size); 
 
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
    
    //TODO, Acutally check it...
    *digest_match = true;
    *signature_match = true;
    return 0; 
}

int 
ecall_end_application_deployment(char* application_id)
{
    EMSG("ecall_end_application_deployment");

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
    TA_UUID,
    1 * 1024 * 1024,
    12 * 1024,
    0,
    "0.0.1",
    
    "ConfidentialPackageManager")

int enc_main(void)
{
    int ret = 0;
    int offset;

    EMSG("Starting ConfidentialPackageManager Instance configuration");
    ocall_log(&ret, "Starting ConfidentialPackageManager Instance configuration");
    
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
        ocall_log(0, "mbedtls_ctr_drbg_seed failed.");
        goto error_ctr_drbg_seed;
    }

    // Initialize RSA context.
    ret = mbedtls_pk_setup(&m_pk_context, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    if (ret != 0)
    {
        ocall_log(0, "mbedtls_pk_setup failed.");
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
        ocall_log(0, "mbedtls_rsa_gen_key failed\n");
        goto error_keygen;
    }
    
    ret = mbedtls_pk_write_pubkey_der(&m_pk_context, public_key, sizeof(public_key));
    if (ret) {
        public_key_size = ret;
        if (public_key_size < sizeof(public_key) ) {
            offset = sizeof(public_key)-public_key_size;
            memmove(public_key, &(public_key[offset]), public_key_size );
        }
        ret = 0;
    }
    else{
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

