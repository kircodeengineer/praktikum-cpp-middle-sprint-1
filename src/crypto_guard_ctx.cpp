#include "crypto_guard_ctx.h"

#include <array>
#include <cstdint>
#include <iomanip>
#include <memory>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <print>
#include <stdexcept>
#include <vector>

namespace CryptoGuard {
class CryptoGuardCtx::Impl {
private:
    struct AesCipherParams {
        static const size_t KEY_SIZE = 32;             // AES-256 key size
        static const size_t IV_SIZE = 16;              // AES block size (IV length)
        const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

        int encrypt;                              // 1 for encryption, 0 for decryption
        std::array<unsigned char, KEY_SIZE> key;  // Encryption key
        std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
    };

    AesCipherParams CreateChiperParamsFromPassword(std::string_view password) const {
        AesCipherParams params;
        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                    reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                    params.key.data(), params.iv.data());

        if (result == 0) {
            throw std::runtime_error{"Failed to create a key from password"};
        }

        return params;
    };

    struct EVPMdCtxDeleter {
        void operator()(EVP_MD_CTX *ctx) {
            if (ctx)
                EVP_MD_CTX_free(ctx);
        }
    };

    using EVPMdCtxPtr = std::unique_ptr<EVP_MD_CTX, EVPMdCtxDeleter>;

    struct EVPCipherCtxDeleter {
        void operator()(EVP_CIPHER_CTX *ctx) {
            if (ctx)
                EVP_CIPHER_CTX_free(ctx);
        }
    };

    using EVPCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EVPCipherCtxDeleter>;

    static const int SUCCESS_EVP{1};
    static const size_t BUFFER_SIZE{4096};
    [[nodiscard]] std::string GetOpenSslError() const {
        auto err{ERR_get_error()};
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        return std::string{err_buf};
    };

public:
    Impl() { OpenSSL_add_all_algorithms(); }

    ~Impl() {
        EVP_cleanup();
        CRYPTO_cleanup_all_ex_data();
    };

    enum class CRYPT_TYPE { ENCRYPT, DECRYPT };

    void CryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password,
                   const CRYPT_TYPE &cryptType) const {
        if (!inStream.good())
            throw std::runtime_error("CryptFile function. InStream not in good state at beginning");

        if (!outStream.good())
            throw std::runtime_error("CryptFile function. OutStream not in good state at beginning");

        AesCipherParams params{CreateChiperParamsFromPassword(password)};

        switch (cryptType) {
        case CRYPT_TYPE::DECRYPT:
            params.encrypt = 0;
            break;
        case CRYPT_TYPE::ENCRYPT:
            params.encrypt = 1;
            break;
        default:
            throw std::runtime_error("CryptFile function. Unknown CryptType");
        }

        EVPCipherCtxPtr ctx(EVP_CIPHER_CTX_new());

        if (!ctx)
            throw std::runtime_error("CryptFile function. Failed to create cipher context");

        if (EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt) !=
            SUCCESS_EVP)
            throw std::runtime_error("CryptFile function. OpenSSL " + GetOpenSslError());

        std::vector<std::uint8_t> inBuf(BUFFER_SIZE);
        std::vector<std::uint8_t> outBuf(BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);
        std::int32_t outLen{};

        do {
            inStream.read(reinterpret_cast<char *>(inBuf.data()), BUFFER_SIZE);

            auto bytesRead{inStream.gcount()};

            if (!bytesRead)
                break;

            if (EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), static_cast<int>(bytesRead)) !=
                SUCCESS_EVP)
                throw std::runtime_error("CryptFile function. OpenSSL " + GetOpenSslError());

            if (!outStream.good())
                throw std::runtime_error("CryptFile function. OutStream not in good state while reading input file");

            outStream.write(reinterpret_cast<const char *>(outBuf.data()), outLen);

            if (!outStream.good())
                throw std::runtime_error("CryptFile function. OutStream failed while writing encrypted file");
        } while (inStream);

        if (inStream.eof()) {
            if (EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen) != SUCCESS_EVP)
                throw std::runtime_error("CryptFile function. OpenSSL " + GetOpenSslError());

            if (!outStream.good())
                throw std::runtime_error("CryptFile function. OutStream failed after finalization of cipher");

            outStream.write(reinterpret_cast<const char *>(outBuf.data()), outLen);

            if (!outStream.good())
                throw std::runtime_error(
                    "CryptFile function. OutStream failed while writing data after finalization of cipher");
        } else {
            throw std::runtime_error("CryptFile function. InStream failed after reading full file");
        }

        if (!outStream)
            throw std::runtime_error("CryptFile function. OutStream failed after completed encryption");

        outStream.flush();
    }

    std::string CalculateChecksum(std::iostream &inStream) const {
        EVPMdCtxPtr ctx(EVP_MD_CTX_new());
        std::uint8_t mdValue[EVP_MAX_MD_SIZE];
        std::uint32_t mdLen{};

        if (!ctx)
            throw std::runtime_error("CalculateChecksum function. Failed to create md context");

        if (EVP_DigestInit_ex2(ctx.get(), EVP_sha256(), NULL) != SUCCESS_EVP)
            throw std::runtime_error("CalculateChecksum function. OpenSSL " + GetOpenSslError());

        std::vector<std::uint8_t> inBuf(BUFFER_SIZE);

        do {
            inStream.read(reinterpret_cast<char *>(inBuf.data()), BUFFER_SIZE);

            auto bytesRead{inStream.gcount()};

            if (!bytesRead)
                break;

            if (EVP_DigestUpdate(ctx.get(), inBuf.data(), bytesRead) != SUCCESS_EVP)
                throw std::runtime_error("CalculateChecksum function. OpenSSL " + GetOpenSslError());
        } while (inStream);

        if (inStream.eof()) {
            if (EVP_DigestFinal_ex(ctx.get(), mdValue, &mdLen) != SUCCESS_EVP)
                throw std::runtime_error("CalculateChecksum function. OpenSSL " + GetOpenSslError());
        } else {
            throw std::runtime_error("CalculateChecksum function. InStream failed after reading full file");
        }

        std::stringstream ss;
        ss << std::hex << std::setfill('0');

        for (std::uint32_t i = 0; i < mdLen; ++i) {
            ss << std::setw(2) << static_cast<std::int32_t>(mdValue[i]);
        }

        return ss.str();
    }
};

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()) {};

CryptoGuardCtx::~CryptoGuardCtx() {};

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) const {
    pImpl_->CryptFile(inStream, outStream, password, Impl::CRYPT_TYPE::ENCRYPT);
}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) const {
    pImpl_->CryptFile(inStream, outStream, password, Impl::CRYPT_TYPE::DECRYPT);
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) const {
    return pImpl_->CalculateChecksum(inStream);
}
}  // namespace CryptoGuard
