#ifndef _AES_H
#define _AES_H
#include <stdint.h>
#include <stdbool.h>

#include <linux/ioctl.h>

#define AES_BLOCK_SIZE		16
#define AES_KEYSIZE_128		AES_BLOCK_SIZE
#define AES_KEYSIZE_256		(AES_BLOCK_SIZE * 2)
#define AES_KEYSIZE_512		(AES_BLOCK_SIZE * 4)
#define AES_KEYSIZE 		AES_KEYSIZE_128


#define TEGRA_CRYPTO_CBC	(1UL << 1)

struct tegra_crypt_req {
	unsigned int op;
	bool encrypt;
	char key[AES_KEYSIZE_512];
	int keylen;
	char iv[AES_BLOCK_SIZE];
	unsigned int ivlen;
	unsigned char *plaintext;
	unsigned char *result;
	unsigned int plaintext_sz;
	unsigned int skip_key;
	unsigned int skip_iv;
	bool skip_exit;
};

#define TEGRA_CRYPTO_IOCTL_NEED_SSK		_IOWR(0x98, 100, int)
#define TEGRA_CRYPTO_IOCTL_PROCESS_REQ	_IOWR(0x98, 101, struct tegra_crypt_req)

typedef void * nvaes_ctx;
nvaes_ctx nvaes_open();
void nvaes_close(nvaes_ctx);

int nvaes_encrypt(nvaes_ctx, unsigned char *, int, unsigned char *, int, unsigned char *);
int nvaes_decrypt(nvaes_ctx, unsigned char *, int, unsigned char *, int, unsigned char *);
int nvaes_sign(nvaes_ctx, unsigned char *, int, unsigned char *);

int nvaes_use_ssk(nvaes_ctx, int);
void nvaes_set_key(nvaes_ctx, char[AES_BLOCK_SIZE]);

int nvaes_encrypt_fd(nvaes_ctx, int, int);
int nvaes_decrypt_fd(nvaes_ctx, int, int);
int nvaes_sign_fd(nvaes_ctx, int, unsigned char *);

#define NVAES_TEGRA_DEVICE "/dev/tegra-crypto"
#define NVAES_PAGE_SIZE 4096
#define NVAES_PADDED_SIZE(x) (x + AES_BLOCK_SIZE - (x % AES_BLOCK_SIZE))
#endif
