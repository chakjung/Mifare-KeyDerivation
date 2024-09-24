#include <iomanip>
#include <iostream>

#include <openssl/evp.h>

#define EVP_MAX_BLOCK_LENGTH 32
struct CMAC_CTX_st {
    /* Cipher context to use */
    EVP_CIPHER_CTX *cctx;
    /* Keys k1 and k2 */
    unsigned char k1[EVP_MAX_BLOCK_LENGTH];
    unsigned char k2[EVP_MAX_BLOCK_LENGTH];
    /* Temporary block */
    unsigned char tbl[EVP_MAX_BLOCK_LENGTH];
    /* Last (possibly partial) block */
    unsigned char last_block[EVP_MAX_BLOCK_LENGTH];
    /* Number of bytes in last block: -1 means context not initialised */
    int nlast_block;
};
#include <openssl/cmac.h>

#include <string.h>
int CMAC_Final_MOD(CMAC_CTX *ctx, unsigned char *out, size_t *poutlen) {
    int bl = 16;

    if (ctx->nlast_block == -1) return 0;

    if (poutlen != NULL) *poutlen = (size_t)bl;
    if (!out) return 1;

    // NXP demands padding to be done on a 32-byte basis
    memcpy(out, ctx->last_block, ctx->nlast_block);

    if (EVP_Cipher(ctx->cctx, out, out, bl) <= 0) {
        OPENSSL_cleanse(out, bl);
        return 0;
    }
    return 1;
}

int main() {
    const unsigned char MasterKey[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                       0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    const unsigned char UID[] = {0x04, 0x79, 0x3D, 0x21, 0x80, 0x1D, 0x80};
    const unsigned char sectorNumber = 5;

    unsigned char cmacInput[32] = {};
    cmacInput[0] = 0x01;
    for (unsigned char i = 0, j = 1; i < 7; ++i, ++j) cmacInput[j] = UID[i];
    cmacInput[8] = sectorNumber;
    cmacInput[9] = 0x80;

    CMAC_CTX *ctx = CMAC_CTX_new();
    CMAC_Init(ctx, MasterKey, 16, EVP_aes_128_cbc(), NULL);

    for (unsigned char i = 0, j = 16; i < 16; ++i, ++j) cmacInput[j] = ctx->k2[i];

    std::cout << "CMAC Input:" << std::endl;
    for (unsigned char i = 0; i < 32; ++i)
        std::cout << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << +cmacInput[i] << ' ';
    std::cout << '\n' << std::endl;

    std::cout << "CMAC Key:" << std::endl;
    for (unsigned char i = 0; i < 16; ++i)
        std::cout << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << +MasterKey[i] << ' ';
    std::cout << '\n' << std::endl;

    CMAC_Update(ctx, cmacInput, 32);

    size_t cmacOutputLen = 0;
    unsigned char cmacOutput[EVP_MAX_BLOCK_LENGTH] = {};
    CMAC_Final_MOD(ctx, cmacOutput, &cmacOutputLen);
    CMAC_CTX_free(ctx);

    std::cout << "CMAC Output:" << std::endl;
    for (size_t i = 0; i < cmacOutputLen; ++i)
        std::cout << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << +cmacOutput[i] << ' ';
    std::cout << '\n' << std::endl;

    unsigned char diversifiedMifareKey[6];
    for (unsigned char i = 0; i < 6; ++i) diversifiedMifareKey[i] = cmacOutput[i];
    std::cout << "Diversified Mifare Key:" << std::endl;
    for (unsigned char i = 0; i < 6; ++i)
        std::cout << std::uppercase << std::hex << std::setfill('0') << std::setw(2) << +diversifiedMifareKey[i] << ' ';
    std::cout << '\n' << std::endl;

    return 0;
}