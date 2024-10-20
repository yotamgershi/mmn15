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
#include "AESWrapper.h"
#include "Base64Wrapper.h"
#include "RSAWrapper.h"

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

    // Create the sign-up request (constructor will handle header and payload)
    Request request(clientID_, VERSION, RequestCode::SIGN_UP, name_);

    // Send the full request (header + payload)
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
        if (response.getResponseCode() == ResponseCodes::SIGN_UP_SUCCESS) {
            std::string receivedClientID(response.getPayload().begin(), response.getPayload().begin() + 16);
            clientID_ = receivedClientID;
            std::cout << "Sign-up successful! Received client ID (hex): ";

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

void Client::writeToMeInfo(Base64Wrapper& base64, const std::string& clientName, const std::string& aesKey, const std::string& clientID) {
    std::ofstream meFile("me.info");
    if (!meFile) {
        std::cerr << "Error: Unable to open me.info for writing." << std::endl;
        return;
    }

    // Write client name
    meFile << clientName << std::endl;

    // Convert client ID to hex format
    std::ostringstream oss;
    for (unsigned char c : clientID) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)(c & 0xff);
    }

    // Write client ID in hex format
    meFile << oss.str() << std::endl;

    // Convert AES key to Base64 using Base64Wrapper::encode
    std::string aesKeyBase64 = base64.encode(aesKey);
    meFile << aesKeyBase64 << std::endl;
    meFile.close();
}


void Client::createAndSaveAESKey() {
    // Create AES keys (adapted for AES instead of RSA)
    Base64Wrapper base64;
    AESWrapper aesWrapper;

    // Set AES key for the client
    this->setAESKey(aesWrapper.getKey());
    if (this->aes_key_[0] == '\0') {
    std::cerr << "Error: AES key not generated or set." << std::endl;
    return;
    }

    std::string aesKeyStr(reinterpret_cast<const char*>(this->aes_key_), DEFAULT_KEYLENGTH);
    std::cout << "AES key generated successfully: " << base64.encode(aesKeyStr) << std::endl;


    // Save the AES key to "priv.key"
    saveAESKeyToFile();  // This will save the key to "priv.key" by default

    // Create 'me.info' to store client info and AES key
    // std::string aesKeyStr(reinterpret_cast<const char*>(this->aes_key_), DEFAULT_KEYLENGTH);
    writeToMeInfo(base64, this->name_, aesKeyStr, this->clientID_);

}

void Client::saveAESKeyToFile(const std::string& filename) {
    Base64Wrapper base64;
    // Convert unsigned char[] to std::string
    std::string aesKeyStr(reinterpret_cast<const char*>(this->aes_key_), DEFAULT_KEYLENGTH);

    // Encode the AES key in Base64 format
    std::string aesKeyBase64 = base64.encode(aesKeyStr);

    // Open the file to write the AES key (default is priv.key)
    std::ofstream outFile(filename);
    if (!outFile) {
        std::cerr << "Error: Could not create or open the file: " << filename << std::endl;
        return;
    }

    // Write the Base64 encoded AES key to the file
    outFile << aesKeyBase64 << std::endl;

    outFile.close();
    std::cout << "AES key saved to " << filename << std::endl;
}



bool Client::sendPublicKey() {
    if (public_key_.empty()) {
        std::cerr << "Error: Public key not set. Please generate RSA keys first." << std::endl;
        return false;
    }

    // Create the request for sending the public key (constructor will handle header and payload)
    Request request(clientID_, VERSION, RequestCode::SEND_PUBLIC_KEY, name_, public_key_);

    // Get the full request (header + payload) and send it to the server
    std::vector<uint8_t> fullRequest = request.getRequest();
    send(fullRequest);

    // Receive the server's response
    std::vector<uint8_t> response = receive();

    if (response.empty()) {
        std::cerr << "Error: No response received from the server." << std::endl;
        return false;
    }

    // Process the response using the Response class
    try {
        Response serverResponse(response);

        // Check if the response code indicates success (1600 for AES key reception, 1602 for acknowledgment)
        if (serverResponse.getResponseCode() == ResponseCodes::PUBLIC_KEY_RECEIVED) {
            std::memcpy(this->aes_key_, serverResponse.getAesKey().data(), DEFAULT_KEYLENGTH);

            std::cout << "Public key sent. AES key received and stored successfully." << std::endl;
            return true;
        } else if (serverResponse.getResponseCode() == 1602) {
            std::cout << "Public key successfully acknowledged by the server." << std::endl;
            return true;
        } else {
            std::cerr << "Error: Failed to send public key. Server returned code: " << serverResponse.getResponseCode() << std::endl;
            return false;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error processing server response: " << e.what() << std::endl;
        return false;
    }
}

void hexify(const unsigned char* buffer, unsigned int length)
{
	std::ios::fmtflags f(std::cout.flags());
    	for (size_t i = 0; i < length; i++)
		std::cout << std::setfill('0') << std::setw(2) << (0xFF & buffer[i]) << (((i + 1) % 16 == 0) ? "\n" : " ");
	std::cout << std::endl;
	std::cout.flags(f);
}