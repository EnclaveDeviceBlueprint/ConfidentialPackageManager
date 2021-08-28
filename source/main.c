#include <string.h>
#include <ConfidentialPackageSpecification_t.h>

int ecall_get_device_public_key_data_size(unsigned int* data_size) { return 0; }

int ecall_export_device_public_key(
    unsigned char* data,
    unsigned int data_size) { return 0; }

int ecall_install_application_key(
    char* application_id,
    unsigned char* data,
    unsigned int data_size){ return 0; }

int ecall_begin_application_deployment(char* application_id){ return 0; }

int ecall_initialize_decryption_aes_gcm(
    char* application_id,
    unsigned int key_strength,
    unsigned char* iv,
    unsigned int iv_size,
    unsigned char* tag,
    unsigned int tag_size) { return 0; };

int ecall_add_application_data(
    char* application_id,
    unsigned char* data,
    unsigned int data_size){ return 0; }

int ecall_verify_application_sha256_rsa_pkcs1_v15(
    char* application_id,
    unsigned int key_strength,
    unsigned char* digest,
    unsigned int digest_size,
    unsigned char* signature,
    unsigned int signature_size,
    unsigned char* public_key,
    unsigned int public_key_size,
    bool* digest_match,
    bool* signature_match) { return 0; }

int ecall_end_application_deployment(char* application_id){ return 0; }

/* TODO, check why this isnt present in the flow in yocto */
int __errno_location;

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
