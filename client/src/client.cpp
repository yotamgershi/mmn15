#include <boost/asio.hpp>
#include <iostream>
#include <string>
#include <vector>

int VERSION = 3;

enum RequestCode {
    SIGN_UP = 825,
    SEND_PUBLIC_KEY = 826,
    SIGN_IN = 827,
    SEND_FILE = 828,
    CRC_VALID = 900,
    CRC_INVALID = 901,
    CRC_INVALID_4TH_TIME = 902
};

class Client {
public:
    Client(const std::string& host, const std::string& port);
    void connect();
    void send(const std::vector<uint8_t>& data);
    void close();

private:
    boost::asio::io_context io_context_;
    boost::asio::ip::tcp::resolver resolver_;
    boost::asio::ip::tcp::socket socket_;
    std::string host_;
    std::string port_;
};

Client::Client(const std::string& host, const std::string& port)
    : resolver_(io_context_), socket_(io_context_), host_(host), port_(port) {}

void Client::connect() {
    try {
        boost::asio::ip::tcp::resolver::results_type endpoints = resolver_.resolve(host_, port_);
        boost::asio::connect(socket_, endpoints);
        std::cout << "Connected to server: " << host_ << ":" << port_ << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

void Client::send(const std::vector<uint8_t>& data) {
    try {
        size_t bytes_sent = boost::asio::write(socket_, boost::asio::buffer(data));
        std::cout << "Sent " << bytes_sent << " bytes to the server." << std::endl;

        if (bytes_sent < data.size()) {
            std::cerr << "Warning: Not all data sent to the server!" << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error while sending data: " << e.what() << std::endl;
    }
}

void Client::close() {
    socket_.close();
    std::cout << "Connection closed" << std::endl;
}

// Function to build a sign-up request
std::vector<uint8_t> buildSignUpRequest(const std::string& clientID, const std::string& name) {
    std::vector<uint8_t> request;
    std::string paddedClientID = clientID;

    // Ensure Client ID is exactly 16 bytes (pad with zeros if necessary)
    if (paddedClientID.size() < 16) {
        paddedClientID.append(16 - paddedClientID.size(), '\0');  // Pad with null bytes
    }

    // Add padded Client ID to the request (16 bytes)
    request.insert(request.end(), paddedClientID.begin(), paddedClientID.end());

    // Add Version (1 byte)
    request.push_back(VERSION);

    // Add Request Code (2 bytes, little-endian)
    request.push_back(SIGN_UP & 0xFF);         // Low byte
    request.push_back((SIGN_UP >> 8) & 0xFF);  // High byte

    // Build and encode payload
    std::string payload = name + '\0';  // Null-terminate the name
    uint32_t payloadsize = static_cast<uint32_t>(payload.size());

    // Payload Size (4 bytes, little-endian)
    request.push_back(payloadsize & 0xFF);
    request.push_back((payloadsize >> 8) & 0xFF);
    request.push_back((payloadsize >> 16) & 0xFF);
    request.push_back((payloadsize >> 24) & 0xFF);

    // Add Payload to request
    request.insert(request.end(), payload.begin(), payload.end());

    return request;
}
