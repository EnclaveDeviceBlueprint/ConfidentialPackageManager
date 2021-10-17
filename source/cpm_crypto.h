#ifndef _CPM_CRYPTO_H
#define _CPM_CRYPTO_H

#define TODO_MAX_TA_SIZE    (2 * 1024 * 1024)   /* 2MiB */
int cpm_crypto_init(const unsigned char *key, const unsigned char *iv);
int cpm_crypto_update( unsigned char* data, unsigned int data_size);

#endif /* _CPM_CRYPTO_H */
