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
            ParsePublicKeyReceivedResponse();
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

void Response::ParsePublicKeyReceivedResponse() {
    // Check that the payload contains at least the AES key
    if (payload_.size() > 16) {
        // Extract the Encrypted AES key (remaining bytes after Client ID)
        encryptedAESKey_ = std::vector<uint8_t>(payload_.begin() + 16, payload_.end());

        // Output extracted values for debugging
        std::cout << "Public key received!" << std::endl;
        std::cout << "Encrypted AES Key (hex): ";
        for (const auto& byte : encryptedAESKey_) {
            printf("%02x", byte);  // Print AES key as hex
        }
        std::cout << std::endl;
    } else {
        std::cerr << "Error: Payload too short to contain AES key" << std::endl;
    }
}
