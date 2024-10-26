#include "requests.hpp"
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include "client.hpp"

// Constructor that builds the request based on the request code
Request::Request(const std::string& clientID, uint8_t version, uint16_t requestCode, const std::string& name_, const std::string& publicKey)
    : clientID_(clientID), version_(version), requestCode_(requestCode), payloadSize_(0) {

    // Ensure clientID is exactly 16 bytes (pad or truncate if necessary)
    if (clientID_.length() > 16) {
        clientID_ = clientID_.substr(0, 16);  // Truncate to 16 bytes
    } else if (clientID_.length() < 16) {
        clientID_.resize(16, '\0');  // Pad with null characters
    }

    // Add Client ID to request (16 bytes)
    request_.insert(request_.end(), clientID_.begin(), clientID_.end());

    // Add Version (1 byte)
    request_.push_back(version_);

    // Add Request Code (2 bytes, little-endian)
    request_.push_back(requestCode_ & 0xFF);         // Low byte
    request_.push_back((requestCode_ >> 8) & 0xFF);  // High byte

    // Add Placeholder for Payload Size (4 bytes, initially 0)
    for (int i = 0; i < 4; ++i) {
        request_.push_back(0);  // Placeholder, to be updated later
    }

    // Call buildRequest to construct the correct payload based on request code
    buildRequest(requestCode, name_, publicKey);
}

// Function that dispatches the correct request-building function
void Request::buildRequest(uint16_t requestCode, const std::string& name, const std::string& publicKey) {
    std::cout << "Request code in buildRequest: " << requestCode << std::endl;
    switch (requestCode) {
        case RequestCode::SIGN_UP:
            buildSignUpRequest(name);
            break;
        case RequestCode::SEND_PUBLIC_KEY:
            buildSendPublicKeyRequest(name, publicKey);
            break;
        case RequestCode::SIGN_IN:
            buildSignInRequest(name);
            break;
        case RequestCode::CRC_INVALID:
        default:
            throw std::runtime_error("Unknown request code: " + std::to_string(requestCode));
    }
}

// Build the sign-up request (payload contains only the name)
void Request::buildSignUpRequest(const std::string& name) {
    std::string payload = name + '\0';  // Null-terminate the name
    payload_.insert(payload_.end(), payload.begin(), payload.end());

    // Update the payload size in the header (bytes 19 to 22)
    payloadSize_ = static_cast<uint32_t>(payload_.size());
    request_[19] = payloadSize_ & 0xFF;
    request_[20] = (payloadSize_ >> 8) & 0xFF;
    request_[21] = (payloadSize_ >> 16) & 0xFF;
    request_[22] = (payloadSize_ >> 24) & 0xFF;

    // Append the payload to the full request
    request_.insert(request_.end(), payload_.begin(), payload_.end());
}

// Build the send public key request (payload contains name + public key)
void Request::buildSendPublicKeyRequest(const std::string& name, const std::string& publicKey) {
    // Build the name field (255 bytes, null-terminated)
    std::vector<uint8_t> nameField(255, 0);
    std::memcpy(nameField.data(), name.c_str(), std::min<size_t>(name.length(), 254));  // Copy name
    payload_.insert(payload_.end(), nameField.begin(), nameField.end());

    // Build the public key field (160 bytes)
    std::vector<uint8_t> publicKeyField(160, 0);
    std::memcpy(publicKeyField.data(), publicKey.data(), std::min<size_t>(publicKey.length(), 160));  // Copy public key
    payload_.insert(payload_.end(), publicKeyField.begin(), publicKeyField.end());

    // Update the payload size in the header (bytes 19 to 22)
    payloadSize_ = static_cast<uint32_t>(payload_.size());
    request_[19] = payloadSize_ & 0xFF;
    request_[20] = (payloadSize_ >> 8) & 0xFF;
    request_[21] = (payloadSize_ >> 16) & 0xFF;
    request_[22] = (payloadSize_ >> 24) & 0xFF;

    // Append the payload to the full request
    request_.insert(request_.end(), payload_.begin(), payload_.end());
}

void Request::buildSignInRequest(std::string name) {

    // Clear the current payload
    payload_.clear();

    // Build the name field (255 bytes, null-terminated)
    std::vector<uint8_t> nameField(255, 0);  // Initialize with 255 null bytes
    std::memcpy(nameField.data(), name.c_str(), std::min<size_t>(name.length(), 254));  // Copy name (up to 254 chars)
    
    // Insert the name field into the payload
    payload_.insert(payload_.end(), nameField.begin(), nameField.end());

    // Update the payload size in the request header (assuming payload size starts at byte 19)
    payloadSize_ = static_cast<uint32_t>(payload_.size());  // Calculate the new payload size
    request_[19] = payloadSize_ & 0xFF;        // Byte 1 (LSB)
    request_[20] = (payloadSize_ >> 8) & 0xFF;  // Byte 2
    request_[21] = (payloadSize_ >> 16) & 0xFF; // Byte 3
    request_[22] = (payloadSize_ >> 24) & 0xFF; // Byte 4 (MSB)

    // Append the payload to the full request
    request_.insert(request_.end(), payload_.begin(), payload_.end());
}

void buildSendPacketRequest(
    const std::vector<uint8_t>& clientIdBytes,
    size_t contentSize,  // Content size of the current packet
    size_t origFileSize,  // Original file size
    size_t packetNum,  // Packet number
    size_t totalPackets,  // Total number of packets
    const std::string& fileName,  // File name
    const std::vector<uint8_t>& messageContent,  // Encrypted content of this packet
    std::vector<uint8_t>& requestBuffer  // The final request packet
) {
    if (clientIdBytes.size() != 16) {
        throw std::runtime_error("Client ID must be 16 bytes.");
    }

    // Clear the request buffer before building the packet
    requestBuffer.clear();

    // 1. Add client ID (16 bytes)
    requestBuffer.insert(requestBuffer.end(), clientIdBytes.begin(), clientIdBytes.end());

    // 2. Add version (1 byte, assuming version = 3)
    requestBuffer.push_back(VERSION);

    // 3. Add request code for SEND_FILE (828 in little-endian, 2 bytes)
    requestBuffer.push_back(0x3C);  // Lower byte of 828
    requestBuffer.push_back(0x03);  // Upper byte of 828

    // 4. Calculate and add payload size (4 bytes, little-endian)
    size_t payloadSize = 4 + 4 + 255 + messageContent.size();  // Adjusted calculation
    requestBuffer.push_back(static_cast<uint8_t>(payloadSize & 0xFF));
    requestBuffer.push_back(static_cast<uint8_t>((payloadSize >> 8) & 0xFF));
    requestBuffer.push_back(static_cast<uint8_t>((payloadSize >> 16) & 0xFF));
    requestBuffer.push_back(static_cast<uint8_t>((payloadSize >> 24) & 0xFF));

    // 5. Add original file size (4 bytes, little-endian)
    requestBuffer.push_back(static_cast<uint8_t>(origFileSize & 0xFF));
    requestBuffer.push_back(static_cast<uint8_t>((origFileSize >> 8) & 0xFF));
    requestBuffer.push_back(static_cast<uint8_t>((origFileSize >> 16) & 0xFF));
    requestBuffer.push_back(static_cast<uint8_t>((origFileSize >> 24) & 0xFF));

    // 6. Add packet number and total packets (2 + 2 bytes, little-endian)
    requestBuffer.push_back(static_cast<uint8_t>(packetNum & 0xFF));         // Packet number (lower byte)
    requestBuffer.push_back(static_cast<uint8_t>((packetNum >> 8) & 0xFF));  // Packet number (upper byte)
    requestBuffer.push_back(static_cast<uint8_t>(totalPackets & 0xFF));      // Total packets (lower byte)
    requestBuffer.push_back(static_cast<uint8_t>((totalPackets >> 8) & 0xFF));  // Total packets (upper byte)

    // 7. Add the file name (255 bytes, padded with null bytes)
    if (fileName.size() > 255) {
        throw std::runtime_error("File name exceeds 255 characters.");
    }
    requestBuffer.insert(requestBuffer.end(), fileName.begin(), fileName.end());  // Insert the file name
    requestBuffer.insert(requestBuffer.end(), 255 - fileName.size(), 0);  // Padding with null bytes

    // 8. Add the message content (messageContent.size() should be <= MAX_CONTENT_SIZE)
    requestBuffer.insert(requestBuffer.end(), messageContent.begin(), messageContent.end());
}

// Free function to build the CRC_VALID request buffer
std::vector<uint8_t> buildCRCValidRequestBuffer(
    const std::string& clientID,
    int version,                    // Using int for VERSION to match your variable type
    RequestCode requestCode,        // Enum for request code; can cast to uint16_t inside function if needed
    const std::string& fileName) {
    
    std::vector<uint8_t> requestBuffer;
    std::vector<uint8_t> payload;
    uint32_t payloadSize;

    // Ensure clientID is exactly 16 bytes (pad or truncate if necessary)
    std::string clientIDPadded = clientID;
    if (clientIDPadded.length() > 16) {
        clientIDPadded = clientIDPadded.substr(0, 16);  // Truncate to 16 bytes
    } else if (clientIDPadded.length() < 16) {
        clientIDPadded.resize(16, '\0');  // Pad with null characters
    }

    // Add Client ID to request (16 bytes)
    requestBuffer.insert(requestBuffer.end(), clientIDPadded.begin(), clientIDPadded.end());

    // Add Version (1 byte)
    requestBuffer.push_back(version);

    // Add Request Code (2 bytes, little-endian)
    requestBuffer.push_back(requestCode & 0xFF);         // Low byte
    requestBuffer.push_back((requestCode >> 8) & 0xFF);  // High byte

    // Add Placeholder for Payload Size (4 bytes, initially 0)
    for (int i = 0; i < 4; ++i) {
        requestBuffer.push_back(0);  // Placeholder, to be updated later
    }

    // Ensure the file name is within 255 bytes
    std::string fileNamePadded = fileName;
    if (fileNamePadded.length() > 255) {
        fileNamePadded = fileNamePadded.substr(0, 255);  // Truncate if longer than 255 bytes
    } else {
        fileNamePadded.resize(255, '\0');  // Pad with null characters to make it exactly 255 bytes
    }

    // Add the file name to the payload
    payload.insert(payload.end(), fileNamePadded.begin(), fileNamePadded.end());

    // Calculate and set payload size
    payloadSize = static_cast<uint32_t>(payload.size());
    requestBuffer[19] = payloadSize & 0xFF;         // Byte 1 (LSB)
    requestBuffer[20] = (payloadSize >> 8) & 0xFF;  // Byte 2
    requestBuffer[21] = (payloadSize >> 16) & 0xFF; // Byte 3
    requestBuffer[22] = (payloadSize >> 24) & 0xFF; // Byte 4 (MSB)

    // Append the payload (file name) to the request buffer
    requestBuffer.insert(requestBuffer.end(), payload.begin(), payload.end());

    std::cout << "CRC request built successfully." << std::endl;

    return requestBuffer;
}
