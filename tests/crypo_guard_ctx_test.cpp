
#include "crypto_guard_ctx.h"

#include <gtest/gtest.h>
#include <sstream>
#include <stdexcept>
#include <string>

#include <iomanip>

class CryptoGuardCtxTest : public ::testing::Test {
    void SetUp() override {
        std::stringstream etalonCheckSumStr{"104 117 56 87 33 127 100 80 212 125 0 108 33 47 69 97 70 47 165 150 43 "
                                            "192 133 123 92 205 93 43 116 129 104 152"};
        std::int32_t number{};
        std::vector<std::uint8_t> etalon;
        while (etalonCheckSumStr >> number) {
            etalon.emplace_back(static_cast<std::uint8_t>(number));
        }
        etalonEncryptedOriginalInputFile.write(reinterpret_cast<const char *>(etalon.data()), etalon.size());
    }

protected:
    std::string etalonChecksum{"6df4de4ab9d498f607d8c3cb490df2c55400137c9a7f5c65b15fb8477183a736"};
    std::stringstream etalonOriginalInputFile{"PraktikumMiddleCppSprint1"};
    std::stringstream etalonEncryptedOriginalInputFile;
    std::string password{"student"};
};

TEST_F(CryptoGuardCtxTest, TestSuccessChecksum) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    EXPECT_EQ(cryptoCtx.CalculateChecksum(etalonOriginalInputFile), etalonChecksum);
}

TEST_F(CryptoGuardCtxTest, TestFailedInputStreamChecksum) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream ss;
    ss.setstate(std::ios::failbit);
    ASSERT_THROW(cryptoCtx.CalculateChecksum(ss), std::runtime_error);
}

TEST_F(CryptoGuardCtxTest, TestSuccesEncrypt) {  //+2
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream ss;
    cryptoCtx.EncryptFile(etalonOriginalInputFile, ss, password);
    EXPECT_EQ(ss.str(), etalonEncryptedOriginalInputFile.str());
}

TEST_F(CryptoGuardCtxTest, TestFailedInputStreamEncrypt) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream inputStream;
    inputStream.setstate(std::ios::failbit);
    std::stringstream outputStream;
    ASSERT_THROW(cryptoCtx.EncryptFile(inputStream, outputStream, password), std::runtime_error);
}

TEST_F(CryptoGuardCtxTest, TestFailedOutputStreamEncrypt) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream inputStream;
    std::stringstream outputStream;
    outputStream.setstate(std::ios::failbit);
    ASSERT_THROW(cryptoCtx.EncryptFile(inputStream, outputStream, password), std::runtime_error);
}

TEST_F(CryptoGuardCtxTest, TestSuccesDecrypt) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream ss;
    cryptoCtx.DecryptFile(etalonEncryptedOriginalInputFile, ss, password);
    EXPECT_EQ(ss.str(), etalonOriginalInputFile.str());
}

TEST_F(CryptoGuardCtxTest, TestSuccesDecryptChecksum) {  // +1
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream ss;
    cryptoCtx.DecryptFile(etalonEncryptedOriginalInputFile, ss, password);
    EXPECT_EQ(cryptoCtx.CalculateChecksum(ss), etalonChecksum);
}

TEST_F(CryptoGuardCtxTest, TestFailedInputStreamDecrypt) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream inputStream;
    inputStream.setstate(std::ios::failbit);
    std::stringstream outputStream;
    ASSERT_THROW(cryptoCtx.DecryptFile(inputStream, outputStream, password), std::runtime_error);
}

TEST_F(CryptoGuardCtxTest, TestFailedOutputStreamDecrypt) {
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream inputStream;
    std::stringstream outputStream;
    outputStream.setstate(std::ios::failbit);
    ASSERT_THROW(cryptoCtx.DecryptFile(inputStream, outputStream, password), std::runtime_error);
}