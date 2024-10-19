#include <boost/asio.hpp>
#include <cryptopp/cryptlib.h>
#include <iostream>
#include <string>
#include <vector>

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

std::vector<uint8_t> Client::receive() {
    std::vector<uint8_t> header(7);  // Assuming header is 7 bytes (1 byte version, 2 bytes code, 4 bytes payload size)
    try {
        // First, read the fixed-size header
        boost::asio::read(socket_, boost::asio::buffer(header));

        // Extract the payload size from the header (4 bytes starting at index 3)
        uint32_t payload_size = header[3] | (header[4] << 8) | (header[5] << 16) | (header[6] << 24);

        // Prepare buffer for the full message (header + payload)
        std::vector<uint8_t> full_message(header.size() + payload_size);

        // Copy header to the full_message buffer
        std::copy(header.begin(), header.end(), full_message.begin());

        // Read the payload
        boost::asio::read(socket_, boost::asio::buffer(full_message.data() + header.size(), payload_size));

        std::cout << "Received full message of " << full_message.size() << " bytes." << std::endl;
        return full_message;
    } catch (const std::exception& e) {
        std::cerr << "Error while receiving data: " << e.what() << std::endl;
        return {};  // Return empty vector in case of error
    }
}

std::pair<bool, std::string> Client::signUp(const std::string& clientID, const std::string& name) {
    // Build and send the sign-up request
    std::vector<uint8_t> request = buildSignUpRequest(clientID, name);
    send(request);

    // Use the receive function to get the server's response
    std::vector<uint8_t> response = receive();

    // Check if the response is not empty
    if (response.empty()) {
        return {false, ""};
    }

    // Process the response
    uint8_t version = response[0];  // 1 byte version
    uint16_t code = response[1] | (response[2] << 8);  // 2 bytes for response code
    uint32_t payloadSize = response[3] | (response[4] << 8) | (response[5] << 16) | (response[6] << 24);  // 4 bytes payload size

    if (code == 1600) {
        std::string receivedClientID(response.begin() + 7, response.begin() + 7 + 16);
        clientID_ = receivedClientID;
        std::cout << "Sign-up successful! Received client ID: " << receivedClientID << std::endl;
        return {true, receivedClientID};
    } else if (code == 1601) {
        std::cerr << "Sign-up failed! Name is already taken" << std::endl;
        return {false, ""};
    }

    // Default to failure if the response is unexpected
    return {false, ""};
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
