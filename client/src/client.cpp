#include <boost/asio.hpp>
#include <cryptopp/cryptlib.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <iomanip>

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

Client::Client(const std::string& host, const std::string& port, const std::string& name, const std::string& clientID)
    : resolver_(io_context_), socket_(io_context_), host_(host), port_(port), name_(name), clientID_(clientID) {}

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

void writeClientIDToFile(const std::string& clientID, const std::string& filename = "me.info") {
    std::ofstream outFile(filename);
    if (!outFile) {
        std::cerr << "Error: Could not create or open the file: " << filename << std::endl;
        return;
    }
    outFile << clientID;
    std::cout << "Client ID written to " << filename << std::endl;
}

std::tuple<std::string, std::string, std::string, std::string> readTransferInfo(const std::string& filename) {
    std::ifstream file(filename);
    std::string serverInfo, host, port, clientName, filePath;

    if (file.is_open()) {
        std::getline(file, serverInfo);

        // Parse the host and port (split by ':')
        size_t colonPos = serverInfo.find(':');
        if (colonPos != std::string::npos) {
            host = serverInfo.substr(0, colonPos);
            port = serverInfo.substr(colonPos + 1);
        } else {
            std::cerr << "Error: Invalid server info format in transfer.info." << std::endl;
        }

        std::getline(file, clientName);

        std::getline(file, filePath);

    } else {
        std::cerr << "Error: Unable to open file: " << filename << std::endl;
    }

    return {host, port, clientName, filePath};  // Return the host, port, clientName, and filePath
}

bool fileExists(const std::string& filename) {
    std::ifstream infile(filename);
    return infile.good();
}

std::pair<bool, std::string> Client::signUp() {
    if (fileExists("me.info")) {
        std::cerr << "Error: Client ID already exists. Please delete 'me.info' to sign up again." << std::endl;
        return {false, ""};
    }

    std::vector<uint8_t> request = buildSignUpRequest(name_);
    send(request);

    std::vector<uint8_t> response = receive();

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
    
    std::cout << "Sign-up successful! Received client ID (hex): ";
    writeClientIDToFile(clientID_);

    for (unsigned char c : clientID_) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c & 0xff) << " ";
    }
    std::cout << std::endl; } else if (code == 1601) {
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
std::vector<uint8_t> buildSignUpRequest(const std::string& name) {
    std::vector<uint8_t> request;
    std::string paddedClientID = "ClientID";  // Dummy client ID

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
