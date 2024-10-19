#include <boost/asio.hpp>
#include <cryptopp/cryptlib.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <iomanip>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cstring>

#include "client.hpp"
#include "requests.hpp"
#include "responses.hpp"

int VERSION = 3;



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

void Client::writeToFile(const std::string& filename = "me.info") {
    std::ofstream outFile(filename);
    if (!outFile) {
        std::cerr << "Error: Could not create or open the file: " << filename << std::endl;
        return;
    }

    outFile << name_ << std::endl;
    for (unsigned char c : clientID_) {
        outFile << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c & 0xff) << " ";
    }
    outFile << std::endl;

    std::cout << "Client ID and name written to " << filename << " (plain and hex format)" << std::endl;
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
    // Check if the client ID already exists to avoid duplicate sign-up
    if (fileExists("me.info")) {
        std::cerr << "Error: Client ID already exists. Please delete 'me.info' to sign up again." << std::endl;
        return {false, ""};
    }

    // Create the sign-up request
    Request request(clientID_, VERSION, RequestCode::SIGN_UP);
    request.buildSignUpRequest(name_);
    send(request.getRequest());

    // Receive the response from the server
    std::vector<uint8_t> rawResponse = receive();
    if (rawResponse.empty()) {
        return {false, ""};
    }

    // Parse the response using the Response class
    try {
        Response response(rawResponse);

        // Check if the sign-up was successful (code 1600 for success)
        if (response.getResponseCode() == 1600) {
            std::string receivedClientID(response.getPayload().begin(), response.getPayload().begin() + 16);
            clientID_ = receivedClientID;
            std::cout << "Sign-up successful! Received client ID (hex): ";

            writeToFile();  // Assuming this saves the client ID to a file

            // Display the received Client ID in hexadecimal format
            for (unsigned char c : clientID_) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c & 0xff) << " ";
            }
            std::cout << std::endl;

            return {true, receivedClientID};
        } else if (response.getResponseCode() == 1601) {
            std::cerr << "Sign-up failed! Name is already taken" << std::endl;
            return {false, ""};
        }

    } catch (const std::exception& e) {
        std::cerr << "Error parsing response: " << e.what() << std::endl;
        return {false, ""};
    }

    return {false, ""};  // Default to failure
}




void Client::close() {
    socket_.close();
    std::cout << "Connection closed" << std::endl;
}

void savePrivateKeyToFile(const CryptoPP::RSA::PrivateKey& privateKey, const std::string& filename = "priv.key") {
    using namespace CryptoPP;

    // Create a file to store the private key
    FileSink file(filename.c_str());

    // Use Base64Encoder to make it readable
    Base64Encoder encoder(new Redirector(file));
    privateKey.DEREncode(encoder);  // Encode private key in DER format
    encoder.MessageEnd();  // Complete the encoding process

    std::cout << "Private key saved to " << filename << std::endl;
}

std::pair<std::string, std::string> generateRSAKeyPair() {
    using namespace CryptoPP;
    
    // Random number generator
    AutoSeededRandomPool rng;

    // Generate RSA private key (2048 bits)
    RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, 2048);

    // Generate corresponding RSA public key
    RSA::PublicKey publicKey(privateKey);

    // Save the keys in PEM or base64 encoded strings
    std::string publicKeyStr, privateKeyStr;

    // Convert private key to string (Base64 format)
    StringSink privateSink(privateKeyStr);
    Base64Encoder privateEncoder(new Redirector(privateSink));
    privateKey.DEREncode(privateEncoder);
    privateEncoder.MessageEnd();

    // Convert public key to string (Base64 format)
    StringSink publicSink(publicKeyStr);
    Base64Encoder publicEncoder(new Redirector(publicSink));
    publicKey.DEREncode(publicEncoder);
    publicEncoder.MessageEnd();

    // Save private key to priv.key
    savePrivateKeyToFile(privateKey, "priv.key");

    return {publicKeyStr, privateKeyStr};
}


bool Client::sendPublicKey(const std::string& publicKey) {
    // Create a Request object for sending the public key
    Request request(clientID_, VERSION, RequestCode::SEND_PUBLIC_KEY);  // 826 for sending public key request code

    // Build the sendPublicKey request by adding the payload (name + public key)
    request.buildSendPublicKey(name_, publicKey);

    // Get the full request (header + payload) and send it to the server
    std::vector<uint8_t> fullRequest = request.getRequest();
    send(fullRequest);

    // Receive the server's response
    std::vector<uint8_t> response = receive();

    if (response.empty()) {
        std::cerr << "Error: No response received from the server." << std::endl;
        return false;
    }

    // Process the response
    uint8_t versionResponse = response[0];
    uint16_t responseCode = response[1] | (response[2] << 8);

    if (responseCode == 1602) {  // Assuming 1602 means public key acknowledged
        std::cout << "Public key successfully sent and acknowledged by the server." << std::endl;
        return true;
    } else {
        std::cerr << "Error: Failed to send public key. Server returned code: " << responseCode << std::endl;
        return false;
    }
}

