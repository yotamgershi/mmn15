#include "responses.hpp"
#include <iostream>

// Constructor that parses the header and calls parse()
Response::Response(const std::vector<uint8_t>& response) {
    if (response.size() < 7) {  // At least 7 bytes are required for the header
        throw std::runtime_error("Response too short to contain a valid header");
    }   

    // Parse the header
    version_ = response[0];
    responseCode_ = response[1] | (response[2] << 8);  // Little-endian 2-byte response code
    payloadSize_ = response[3] | (response[4] << 8) | (response[5] << 16) | (response[6] << 24);  // 4-byte payload size

    // Extract the payload if available
    if (response.size() > 7) {
        payload_ = std::vector<uint8_t>(response.begin() + 7, response.end());
    }

    // Call parse based on response code
    parse(responseCode_);
}

// Function to dispatch the parsing based on the response code
void Response::parse(uint16_t responseCode) {
    switch (responseCode) {
        case SIGN_UP_SUCCESS:
            parseSignUpSuccessResponse();
            break;
        case SIGN_UP_FAILURE:
            parseSignUpFailureResponse();
            break;
        case PUBLIC_KEY_RECEIVED:
            parsePublicKeyReceivedResponse();
            break;
        case SIGN_IN_SUCCESS:
            parseSignInSuceessResponse();
            break;
        case SIGN_IN_FAILURE:
            parseSignInFailureResponse();
            break;
        default:
            std::cerr << "Unknown response code: " << responseCode << std::endl;
            break;
    }
}

// Parse the sign-up response (e.g., extract Client ID)
void Response::parseSignUpSuccessResponse() {
    if (payload_.size() >= 16) {
        std::string clientID(payload_.begin(), payload_.begin() + 16);
        std::cout << "Sign-up successful! Client ID: " << clientID << std::endl;
    } else {
        std::cerr << "Error: Payload too short for Client ID" << std::endl;
    }
}

void Response::parseSignInResponse() {
    std::cout << "Sign-in failed! Invalid credentials." << std::endl;
}

void Response::parseSignUpFailureResponse() {
    // Implementation logic for handling sign-up failure response
    std::cerr << "Sign-up failed! Name is already taken." << std::endl;
}

void Response::parsePublicKeyReceivedResponse() {
    if (payload_.size() < 16) {
        std::cerr << "Error: Payload too short to contain AES key" << std::endl;
    }

    // Extract the Encrypted AES key (remaining bytes after Client ID)
    encryptedAESKey_ = std::vector<uint8_t>(payload_.begin() + 16, payload_.end());

    // Output extracted values for debugging
    std::cout << "Public key received!" << std::endl;
    std::cout << "Encrypted AES Key (hex): ";
    for (const auto& byte : encryptedAESKey_) {
        printf("%02x", byte);  // Print AES key as hex
    }
    std::cout << std::endl;
}

void Response::parseSignInSuceessResponse() {
    std::cout << "Sign-in successful!" << std::endl;
}

void Response::parseSignInFailureResponse() {
    std::cout << "Sign-in failed! Invalid credentials." << std::endl;
}

std::string Response::getAESKey() const {
    std::cout << "Response code: " << responseCode_ << std::endl;

    if (responseCode_ == PUBLIC_KEY_RECEIVED || responseCode_ == SIGN_IN_SUCCESS) {
        size_t clientIdSize = 16;  // Client ID is 16 bytes
        
        if (payload_.size() <= clientIdSize) {
            throw std::runtime_error("Payload size is too small for AES key extraction.");
        }

        size_t aesKeySize = payload_.size() - clientIdSize;

        // Extract the Client ID and AES key
        std::vector<uint8_t> clientId(payload_.begin(), payload_.begin() + clientIdSize);
        std::vector<uint8_t> aesKey(payload_.begin() + clientIdSize, payload_.end());

        // Log the Client ID and AES key for debugging
        std::cout << "Client ID: ";
        for (const auto& byte : clientId) {
            std::cout << std::hex << static_cast<int>(byte) << " ";
        }
        std::cout << std::endl;

        std::cout << "AES Key: ";
        for (const auto& byte : aesKey) {
            std::cout << std::hex << static_cast<int>(byte) << " ";
        }
        std::cout << std::endl;

        // Convert the AES key to std::string and return it
        return std::string(aesKey.begin(), aesKey.end());
    } else {
        throw std::runtime_error("Response code does not contain an AES key.");
    }
}

