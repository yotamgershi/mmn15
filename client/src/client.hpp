#ifndef CLIENT_HPP
#define CLIENT_HPP

#include <iostream>
#include <string>
#include <vector>
#include <boost/asio.hpp>
#include <cryptopp/rsa.h>


class Client {
public:
    Client(const std::string& host, const std::string& port, const std::string& name, const std::string& clientID);
    void connect();
    void send(const std::vector<uint8_t>& data);
    void close();
    std::vector<uint8_t> receive();
    std::pair<bool, std::string> signUp();
    void Client::writeToFile(const std::string& filename);
    bool Client::sendPublicKey(const std::string& publicKey);
    std::pair<std::string, std::string> Client::generateRSAKeyPair();

private:
    boost::asio::io_context io_context_;
    boost::asio::ip::tcp::resolver resolver_;
    boost::asio::ip::tcp::socket socket_;
    std::string host_;
    std::string port_;
    std::string clientID_;
    std::string name_;
    std::string private_key_;
    std::string aes_key_;
};

std::tuple<std::string, std::string, std::string, std::string> readTransferInfo(const std::string& filename);
void savePrivateKeyToFile(const CryptoPP::RSA::PrivateKey& privateKey, const std::string& filename);

#endif // CLIENT_HPP
