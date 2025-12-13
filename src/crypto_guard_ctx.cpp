#include "crypto_guard_ctx.h"

#include <openssl/evp.h>
#include <print>

namespace CryptoGuard {
    class CryptoGuardCtx::Impl {
        public:
            Impl() {
                OpenSSL_add_all_algorithms();
                std::print("Impl created\n");
            }

            ~Impl() {
                EVP_cleanup();
                CRYPTO_cleanup_all_ex_data();
                std::print("Impl created\n");
            };
            void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
                std::print("EncryptFile\n");
            }
            void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
                std::print("DecryptFile\n");
            }
            std::string CalculateChecksum(std::iostream &inStream) { 
                std::print("CalculateChecksum\n");
                return "NOT_IMPLEMENTED"; 
            }
    };

    CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()) {};

    CryptoGuardCtx::~CryptoGuardCtx() {};

    void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password){
        pImpl_->EncryptFile(inStream, outStream, password);
    }

    void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password){
        pImpl_->DecryptFile(inStream, outStream, password);
    }

    std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream){
        return pImpl_->CalculateChecksum(inStream);
    }
}  // namespace CryptoGuard
