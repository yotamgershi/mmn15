#include "requests.hpp"
#include <cstring>

// Constructor that builds the request based on the request code
Request::Request(const std::string& clientID, uint8_t version, uint16_t requestCode, const std::string& name, const std::string& publicKey)
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
    buildRequest(requestCode, name, publicKey);
}

// Function that dispatches the correct request-building function
void Request::buildRequest(uint16_t requestCode, const std::string& name, const std::string& publicKey) {
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
        default:
            throw std::runtime_error("Unknown request code");
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

void Request::buildSignInRequest(const std::string& name) {
    // Clear the current payload
    payload_.clear();

    // Build the name field (255 bytes, null-terminated)
    std::vector<uint8_t> nameField(255, 0);  // Initialize with 255 null bytes
    std::memcpy(nameField.data(), name.c_str(), std::min<size_t>(name.length(), 254));  // Copy name (up to 254 chars)

    // Insert the name field into the payload
    payload_.insert(payload_.end(), nameField.begin(), nameField.end());

    // Update the payload size in the header (assuming the payload size starts at byte 19)
    payloadSize_ = static_cast<uint32_t>(payload_.size());  // Calculate the new payload size
    request_[19] = payloadSize_ & 0xFF;        // Byte 1 (LSB)
    request_[20] = (payloadSize_ >> 8) & 0xFF;  // Byte 2
    request_[21] = (payloadSize_ >> 16) & 0xFF; // Byte 3
    request_[22] = (payloadSize_ >> 24) & 0xFF; // Byte 4 (MSB)

    // Append the payload (name field) to the full request
    request_.insert(request_.end(), payload_.begin(), payload_.end());
}
