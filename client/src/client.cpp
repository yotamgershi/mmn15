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
#include <sstream>
#include "client.hpp"
#include "requests.hpp"
#include "responses.hpp"
#include "AESWrapper.h"
#include "Base64Wrapper.h"
#include "RSAWrapper.h"
#include "cksum_new.hpp"

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
        // return {false, ""};
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
    std::cout << "AES key generated successfully" << std::endl;


    // Save the AES key to "priv.key"
    // savePrivateKeyToFile("priv.key");

    // Create 'me.info' to store client info and AES key
    writeToMeInfo(base64, this->name_, aesKeyStr, this->clientID_);
}

void Client::savePrivateKeyToFile(const std::string& filename, std::string privateKey) {
    // Open the file to write the private key (default is priv.key)
    std::ofstream outFile(filename);
    if (!outFile) {
        std::cerr << "Error: Could not create or open the file: " << filename << std::endl;
        return;
    }

    // Change private_key_ to Base64 encoding using Base64Wrapper
    Base64Wrapper base64;
    std::string privateKeyBase64 = base64.encode(privateKey);

    // Write the private key to the file
    outFile << privateKeyBase64 << std::endl;

    outFile.close();
    std::cout << "Private key saved to " << filename << std::endl;
}

bool Client::sendPublicKey() {

    Base64Wrapper base64;
    RSAPrivateWrapper RSAObject;  
    setPrivateKey(RSAObject.getPrivateKey());
    savePrivateKeyToFile("priv.key", RSAObject.getPrivateKey());
	const std::string public_key_ = RSAObject.getPublicKey();
    
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
        } else {
            std::cerr << "Error: Failed to send public key. Server returned code: " << serverResponse.getResponseCode() << std::endl;
            return false;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error processing server response: " << e.what() << std::endl;
        return false;
    }
}

bool Client::signIn() {
    try {
        // Check if me.info exists
        std::ifstream file("me.info");
        std::string nameToUse = name_;
        std::string clientIDToUse = clientID_;

        if (file.good()) {  // If the file exists
            std::cout << "me.info exists, loading name and client ID from file..." << std::endl;

            // Retrieve name and client ID from the file
            std::string fileName = getNameFromFile();
            std::string fileClientID = getClientIDFromFile();

            // If data from the file is valid, update the name and clientID variables
            if (!fileName.empty()) {
                nameToUse = fileName;
            }

            if (!fileClientID.empty()) {
                clientIDToUse = fileClientID;
            }
        } else {
            std::cout << "me.info does not exist, using default client ID and name." << std::endl;
        }

        // Construct the request with the updated or default client ID, version, request code (SIGN_IN), and name
        Request request(clientIDToUse, VERSION, RequestCode::SIGN_IN, nameToUse);

        // Send the request to the server
        send(request.getRequest());

        // Receive the server's response
        Response response = receive();

        // Check if the response indicates a successful sign-in
        if (response.getResponseCode() == ResponseCodes::SIGN_IN_SUCCESS) {
            std::cout << "Sign-in successful!" << std::endl;
            // Get the AES key from the response and set it in the client
            std::string aesKey = response.getAESKey();
            setAESKey(reinterpret_cast<const unsigned char*>(aesKey.data()));
            std::cout << "set AES key: " << this->aes_key_ << std::endl;
            return true;
        } else {
            std::cerr << "Sign-in failed. Error: " << response.getResponseCode() << std::endl;
            return false;
        }
    } catch (const std::exception& e) {
        std::cerr << "An error occurred during sign-in: " << e.what() << std::endl;
        return false;
    }
}

std::string Client::decryptWithPrivateKey(const std::string& encryptedKey) {
    // Assuming RSA decryption, with CryptoPP library
    std::string decryptedKey;
    
    CryptoPP::RSA::PrivateKey privateKey;

    //Load private key from priv.key
    if (!fileExists("priv.key")) {
        std::cerr << "Error: Private key file not found." << std::endl;
        return "";
    }

    // Read the private key from the file
    std::ifstream file("priv.key");
    std::string privateKeyBase64;
    if (file.is_open()) {
        std::getline(file, privateKeyBase64);
    } else {
        std::cerr << "Error: Unable to open priv.key for reading." << std::endl;
        return "";
    }

    CryptoPP::StringSource ss(privateKeyBase64, true, new CryptoPP::Base64Decoder);

    CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
    
    CryptoPP::StringSource ss2(encryptedKey, true,
        new CryptoPP::PK_DecryptorFilter(CryptoPP::AutoSeededRandomPool(), decryptor,
            new CryptoPP::StringSink(decryptedKey)
        )
    );

    return decryptedKey;
}

// Helper function to read specific lines from the file
std::string getLineFromFile(const std::string& filePath, int lineNumber) {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        std::cerr << "Error: Could not open " << filePath << std::endl;
        return "";
    }

    std::string line;
    int currentLine = 0;

    // Read up to the specified line number
    while (std::getline(file, line)) {
        if (currentLine == lineNumber) {
            return line;
        }
        currentLine++;
    }

    std::cerr << "Error: Line " << lineNumber << " not found in " << filePath << std::endl;
    return "";
}

std::string getNameFromFile() {
    return getLineFromFile("me.info", 0);  // First line for the name
}

// Modify this function to ensure that the full client ID is read and sent as bytes
std::string getClientIDFromFile() {
    std::string clientIDHex = getLineFromFile("me.info", 1);  // Read client_id from file as hex

    // Convert the hex string to raw bytes (16 bytes)
    std::vector<uint8_t> clientIDBytes;
    for (size_t i = 0; i < clientIDHex.length(); i += 2) {
        std::string byteString = clientIDHex.substr(i, 2);
        uint8_t byte = (uint8_t) strtol(byteString.c_str(), nullptr, 16);
        clientIDBytes.push_back(byte);
    }

    // Ensure the result is 16 bytes
    if (clientIDBytes.size() != 16) {
        std::cerr << "Error: Client ID is not 16 bytes!" << std::endl;
        return "";
    }

    return std::string(clientIDBytes.begin(), clientIDBytes.end());  // Return as a binary string
}

std::string getAesFromFile() {
    return getLineFromFile("me.info", 2);  // Third line for the AES key
}

void Client::sendFile(const std::string& filePath) {
    // Step 1: Read the file content
    std::cout << "Reading file: " << filePath << std::endl;
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open the file.");
    }

    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> fileContent(fileSize);
    file.read(reinterpret_cast<char*>(fileContent.data()), fileSize);
    file.close();

    // Calculate the CRC value of the file content
    calculateCRC(filePath);

    // Step 2: Initialize AESWrapper with a key (you might already have the key)
    std::cout << "Initializing AES encryption..." << std::endl;
    AESWrapper aesWrapper;  // Use the default constructor to generate a key
    const unsigned char* aesKey = aesWrapper.getKey();  // You can store/use this key later

    std::cout << "Encrypting file content..." << std::endl;
    // Step 3: Encrypt the file content
    // std::string encryptedFile = aesWrapper.encrypt(reinterpret_cast<const char*>(fileContent.data()), fileContent.size());
    std::string encryptedFile = reinterpret_cast<const char*>(fileContent.data());

    std::cout << "File encrypted successfully. Converting to vector" << std::endl;
    // Convert the encrypted file content to std::vector<uint8_t> for further processing
    std::vector<uint8_t> encryptedFileContent(encryptedFile.begin(), encryptedFile.end());

    // Ensure encrypted file content is not empty
    if (encryptedFileContent.empty()) {
        throw std::runtime_error("Encrypted file content is empty.");
    }

    std::cout << "File converted to vector. Sending file by packets..." << std::endl;

    // Ensure MAX_CONTENT_SIZE is properly defined
    if (MAX_CONTENT_SIZE == 0) {
        throw std::runtime_error("MAX_CONTENT_SIZE must be greater than 0.");
    }

    // Step 4: Packetize and send the encrypted file
    size_t totalPackets = (encryptedFileContent.size() + MAX_CONTENT_SIZE - 1) / MAX_CONTENT_SIZE;  // Calculate number of packets
    size_t packetNum = 0;

    // Step 5: Use clientID_ attribute for sending the client ID
    std::string clientIDStr = getClientIDFromFile();
    std::vector<uint8_t> clientIdBytes(clientIDStr.begin(), clientIDStr.end());

    std::vector<uint8_t> fileNameBytes(filePath.begin(), filePath.end());

    while (packetNum < totalPackets) {
        // Extract the next chunk of the file (up to MAX_CONTENT_SIZE bytes)
        size_t start = packetNum * MAX_CONTENT_SIZE;
        size_t end = std::min(start + MAX_CONTENT_SIZE, encryptedFileContent.size());

        std::vector<uint8_t> packetContent(encryptedFileContent.begin() + start, encryptedFileContent.begin() + end);

        // Build the request for the current packet
        std::vector<uint8_t> requestBuffer;
        // Ensure you're passing the correct arguments in the proper order and types
        buildSendPacketRequest(
            clientIdBytes,               // std::vector<uint8_t>
            packetContent.size(),         // size_t (contentSize)
            fileSize,                     // size_t (original file size)
            packetNum,                    // size_t (packet number)
            totalPackets,                 // size_t (total packets)
            filePath,                     // std::string (file name) <--- This should be a string, not a vector
            packetContent,                // std::vector<uint8_t> (message content)
            requestBuffer                 // std::vector<uint8_t> (request buffer)
        );

        // Send the request
        std::cout << "Packet number: " << (packetNum + 1) << " / " << totalPackets << std::endl;
        send(requestBuffer);

        packetNum++;
    }

    Response response = receive();

    if (response.getResponseCode() == ResponseCodes::SEND_FILE_SUCCESS) {
        std::cout << "File sent successfully!" << std::endl;
    } else {
        std::cerr << "Error: File transfer failed. Response code: " << response.getResponseCode() << std::endl;
    }

    // Step 6: Get the CRC value from the response
    uint32_t crcValueFromServer = response.getCRCValue();
    uint32_t crcValueFromClient = getCRCValue();

    std::cout << "Line 515" << std::endl;

    // Construct request for CRC value
    Request request(clientID_, VERSION, RequestCode::CRC_VALID, name_, public_key_);
    request.buildCRCValidRequest(filePath);
    std::cout << "Request built for CRC valid." << std::endl;

    // Send the request to the server
    send(request.getRequest());
    std::cout << "Request sent to server." << std::endl;

    // Receive the server's response
    Response CRCResponse = receive();
    std::cout << "Response received from server." << std::endl;

    // Log the response code
    std::cout << "Response code: " << CRCResponse.getResponseCode() << std::endl;



    // Compare the CRC value from the response with the calculated CRC value
//     if (crcValueFromServer == crcValueFromClient) {
//         std::cout << "CRC matched: " << crcValueFromClient << std::endl;
//     } else {
//         std::cerr << "CRC mismatch! Expected: " << crcValueFromClient << ", Received: " << crcValueFromServer << std::endl;
//     }        
}

void Client::calculateCRC(const std::string& filePath) {
    if (std::filesystem::exists(filePath)) {
        std::filesystem::path fpath = filePath;
        std::ifstream file(filePath.c_str(), std::ios::binary);

        size_t size = std::filesystem::file_size(fpath);
        char* buffer = new char[size];
        file.seekg(0, std::ios::beg);
        file.read(buffer, size);

        // Calculate the CRC using memcrc function from cksum_new.cpp
        crcValue_ = memcrc(buffer, size);

        // Clean up the buffer
        delete[] buffer;

        std::cout << "CRC calculated: " << crcValue_ << std::endl;
    } else {
        std::cerr << "File not found: " << filePath << std::endl;
    }
}

std::vector<uint8_t> Client::getClientID() const {
    std::vector<uint8_t> clientIdBytes(clientID_.begin(), clientID_.end());

    // Pad the client ID to 16 bytes if it is less than 16 bytes
    if (clientIdBytes.size() < 16) {
        clientIdBytes.insert(clientIdBytes.end(), 16 - clientIdBytes.size(), 0);
    }

    return clientIdBytes;
}

// Convert vector<uint8_t> to byte string
std::string bytesToHexString(const std::vector<uint8_t>& buffer) {
    std::ostringstream oss;

    for (const auto& byte : buffer) {
        if (std::isprint(byte)) {
            // If the byte is printable, print it as a character
            oss << byte;
        } else {
            // Otherwise, print the byte in hexadecimal format
            oss << "\\x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
    }

    return oss.str();
}