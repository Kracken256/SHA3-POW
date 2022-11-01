
#include <string>
#include <cstring>
#include <openssl/sha.h>
#include <openssl/evp.h>

namespace SHA3_POW
{
    bool inline check_bits(unsigned char byte, uint8_t bits)
    {
        if (bits > 0 && !(~byte & (0x80 >> 0)))
        {
            return false;
        }
        if (bits > 1 && !(~byte & (0x80 >> 1)))
        {
            return false;
        }
        if (bits > 2 && !(~byte & (0x80 >> 2)))
        {
            return false;
        }
        if (bits > 3 && !(~byte & (0x80 >> 3)))
        {
            return false;
        }
        if (bits > 4 && !(~byte & (0x80 >> 4)))
        {
            return false;
        }
        if (bits > 5 && !(~byte & (0x80 >> 5)))
        {
            return false;
        }
        if (bits > 6 && !(~byte & (0x80 >> 6)))
        {
            return false;
        }
        if (bits > 7 && !(~byte & (0x80 >> 7)))
        {
            return false;
        }
        return true;
    }
    static inline void Compute_SHA3_256(std::string input, std::string *buffer)
    {
        uint32_t digest_length = SHA256_DIGEST_LENGTH;
        const EVP_MD *algorithm = EVP_sha3_256();
        unsigned char digest[digest_length];
        EVP_MD_CTX *context = EVP_MD_CTX_new();
        EVP_DigestInit_ex(context, algorithm, nullptr);
        EVP_DigestUpdate(context, input.c_str(), input.length());
        EVP_DigestFinal_ex(context, digest, &digest_length);
        buffer->assign(std::string((const char *)digest, digest_length));
        EVP_MD_CTX_free(context);
    }
    static bool Compute_SHA3_POW(const std::string input, uint16_t difficulty, uint64_t *best_nonce)
    {
        if (difficulty > 256)
        {
            return false;
        }
        unsigned char cmp_test[32];
        memset(cmp_test, 0, 32);
        uint64_t nonce = 0;
        bool d1 = difficulty < 8;
        if (d1)
        {
            while (1)
            {
                std::string digest;
                Compute_SHA3_256(input + std::to_string(nonce), &digest);
                if (d1)
                {
                    if (!check_bits(digest[0], difficulty))
                    {
                        nonce++;
                        continue;
                    }
                    else
                    {
                        *best_nonce = nonce;
                        return true;
                    }
                }
            }
        }
        const uint8_t d8 = difficulty / 8;
        const uint8_t last_bits_count = difficulty % 8;
        while (1)
        {
            std::string digest;
            Compute_SHA3_256(input + std::to_string(nonce), &digest);
            if (memcmp(digest.c_str(), cmp_test, d8) != 0)
            {
                nonce++;
                continue;
            }
            if (last_bits_count == 0)
            {
                *best_nonce = nonce;
                return true;
            }
            if (!check_bits(digest[d8], last_bits_count))
            {
                nonce++;
                continue;
            }
            *best_nonce = nonce;
            return true;
        }
        return false;
    }
    static bool Verify_SHA3_POW(const std::string input, uint64_t nonce, uint8_t difficulty)
    {
        std::string digest;
        Compute_SHA3_256(input + std::to_string(nonce), &digest);
        if (difficulty < 8)
        {
            if (!check_bits(digest[0], difficulty))
            {
                return false;
            }
            return true;
        }
        unsigned char cmp_test[32];
        memset(cmp_test, 0, 32);
        uint8_t first_bytes = difficulty / 8;
        if (memcmp(digest.c_str(), cmp_test, first_bytes) != 0)
        {
            return false;
        }
        uint8_t last_bits_count = difficulty % 8;
        if (last_bits_count == 0)
        {
            return true;
        }
        if (!check_bits(digest[first_bytes], last_bits_count))
        {
            return false;
        }
        return true;
    }
}