#ifndef _CPM_CRYPTO_H
#define _CPM_CRYPTO_H

int cpm_crypto_init(const unsigned char *key, const unsigned char *iv);
int cpm_crypto_update(unsigned char* data, unsigned int data_size);
int cpm_crypto_finish(unsigned char* tag, const unsigned int tag_size);
int cpm_crypto_get_buffer(uint8_t** bufferp, uint32_t *sizep);
#endif /* _CPM_CRYPTO_H */
