#include <iostream>
#include <iomanip>
#include <openssl/des.h>

int main() {
    unsigned char MifareKey[] = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5};
    unsigned char blockAddr = 0x07;
    unsigned char UID[] = {0xF4, 0xEA, 0x54, 0x8E};

    unsigned char tripleDESIn[8];
    for (unsigned char i = 0; i < 4; ++i) tripleDESIn[i] = MifareKey[i];
    tripleDESIn[4] = MifareKey[4] ^ UID[0];
    tripleDESIn[5] = MifareKey[5] ^ UID[1];
    tripleDESIn[6] = blockAddr ^ UID[2];
    tripleDESIn[7] = UID[3];

    std::cout << "Triple DES Input:" << std::endl;
    for (unsigned char i = 0; i < 8; ++i)
        std::cout << std::uppercase << std::hex << std::setfill('0') << std::setw(2) << +tripleDESIn[i] << ' ';
    std::cout << '\n' << std::endl;

    std::cout << "Triple DES Key:" << std::endl;
    const unsigned char tripleDESKey[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                          0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    for (unsigned char i = 0; i < 16; ++i)
        std::cout << std::uppercase << std::hex << std::setfill('0') << std::setw(2) << +tripleDESKey[i] << ' ';
    std::cout << '\n' << std::endl;

    unsigned char tripleDESOut[8];
    DES_key_schedule key1, key2;
    DES_set_key((const_DES_cblock*)tripleDESKey, &key1);
    DES_set_key((const_DES_cblock*)(tripleDESKey + 8), &key2);
    DES_ecb2_encrypt((const_DES_cblock*)tripleDESIn, (DES_cblock*)tripleDESOut, &key1, &key2, true);

    std::cout << "Triple DES Output:" << std::endl;
    for (unsigned char i = 0; i < 8; ++i)
        std::cout << std::uppercase << std::hex << std::setfill('0') << std::setw(2) << +tripleDESOut[i] << ' ';
    std::cout << '\n' << std::endl;

    unsigned char diversifiedMifareKey[6];
    for (unsigned char i = 0, j = 1; i < 6; ++i, ++j) diversifiedMifareKey[i] = tripleDESOut[j];
    std::cout << "Diversified Mifare Key:" << std::endl;
    for (unsigned char i = 0; i < 6; ++i)
        std::cout << std::uppercase << std::hex << std::setfill('0') << std::setw(2) << +diversifiedMifareKey[i] << ' ';
    std::cout << '\n' << std::endl;

    return 0;
}