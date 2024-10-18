#include <boost/asio.hpp>
#include <iostream>
#include <string>

#include "client.hpp"

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

SignUpRequest::SignUpRequest(const std::string& clientID, const std::string& name) {
    clientID_ = clientID;
    version_ = VERSION;
    code_ = 825;
    payloadsize_ = name.size();
    name_ = name;

    if (name_.size() > 255)
        name_ = name_.substr(0, 254);
}

std::vector<uint8_t> SignUpRequest::buildRequest() {
    std::vector<uint8_t> request;

    // Ensure Client ID is exactly 16 bytes (pad with zeros if necessary)
    std::string paddedClientID = clientID_;
    if (paddedClientID.size() < 16) {
        paddedClientID.append(16 - paddedClientID.size(), '\0');  // Pad with null bytes
    }

    // Add padded Client ID to the request (16 bytes)
    request.insert(request.end(), paddedClientID.begin(), paddedClientID.end());

    // Add Version (1 byte)
    request.push_back(version_);

    // Add Request Code (2 bytes, little-endian)
    request.push_back(code_ & 0xFF);         // Low byte
    request.push_back((code_ >> 8) & 0xFF);  // High byte

    // Build and encode payload
    std::string payload = name_ + '\0';  // Null-terminate the name
    payloadsize_ = payload.size();

        // Payload Size (4 bytes, little-endian)
        request.push_back(payloadsize_ & 0xFF);
        request.push_back((payloadsize_ >> 8) & 0xFF);
        request.push_back((payloadsize_ >> 16) & 0xFF);
        request.push_back((payloadsize_ >> 24) & 0xFF);

    // Add Payload to request
    request.insert(request.end(), payload.begin(), payload.end());

    return request;
}

