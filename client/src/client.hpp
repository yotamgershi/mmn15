#ifndef CLIENT_HPP
#define CLIENT_HPP

#include <iostream>
#include <string>
#include <vector>
#include <boost/asio.hpp>
#include <cryptopp/rsa.h>
#include <cstring>
#include "Base64Wrapper.h"
#include "requests.hpp"
#include "RSAWrapper.h"

const int DEFAULT_KEYLENGTH = 32;
const int MAX_CONTENT_SIZE = 1024;

class Client {
public:
    Client(const std::string& host, const std::string& port, const std::string& name, const std::string& clientID);
    void connect();
    void send(const std::vector<uint8_t>& data);
    void close();
    std::vector<uint8_t> receive();
    std::pair<bool, std::string> signUp();
    bool Client::sendPublicKey();
    void Client::createAndSaveAESKey();
    void Client::setAESKey(const unsigned char* key) {std::memcpy(this->aes_key_, key, DEFAULT_KEYLENGTH);};
    void Client::writeToMeInfo(Base64Wrapper& base64, const std::string& clientName, const std::string& aesKey, const std::string& clientID);
    void Client::saveAESKeyToFile(const std::string& filename = "priv.key");
    std::string Client::getPublicKey() {return public_key_;};
    void setPublicKey(const std::string& publicKey) {public_key_ = publicKey;};
    std::string Client::getAESKey() {return std::string(aes_key_, aes_key_ + DEFAULT_KEYLENGTH);};
    bool Client::signIn();
    void Client::sendFile(const std::string& filePath);
    void calculateCRC(const std::string& filePath);  // Function to calculate CRC from a file
    std::vector<uint8_t> Client::getClientID() const;
    uint32_t Client::getCRCValue() const {return crcValue_;};
    void setPrivateKey(const std::string& privateKey) {private_key_ = privateKey;};
    void savePrivateKeyToFile(const std::string& filename, RSAPrivateWrapper RSAObject);
    void savePrivateKeyToFile(const std::string& filename, std::string privateKey);


private:
    boost::asio::io_context io_context_;
    boost::asio::ip::tcp::resolver resolver_;
    boost::asio::ip::tcp::socket socket_;
    std::string host_;
    std::string port_;
    std::string clientID_;
    std::string name_;
    std::string private_key_;
    std::string public_key_;
    unsigned char aes_key_[DEFAULT_KEYLENGTH];
    std::string Client::decryptWithPrivateKey(const std::string& encryptedKey);
    unsigned long crcValue_;
    void Client::savePrivateKeyToFile(const std::string& filename);
};

std::tuple<std::string, std::string, std::string, std::string> readTransferInfo(const std::string& filename);
std::string getLineFromFile(const std::string& filePath, int lineNumber);
std::string getNameFromFile();
std::string getClientIDFromFile();
std::string getAesFromFile();
bool fileExists(const std::string& filename);
std::string bytesToHexString(const std::vector<uint8_t>& bytes);

#endif // CLIENT_HPP
