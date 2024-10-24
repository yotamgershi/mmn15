#ifndef RESPONSE_HPP
#define RESPONSE_HPP

#include <vector>
#include <string>
#include <stdexcept>
#include <iostream>
#include "cksum_new.hpp"

enum ResponseCodes {
    SIGN_UP_SUCCESS = 1600,
    SIGN_UP_FAILURE = 1601,
    PUBLIC_KEY_RECEIVED = 1602,
    SIGN_IN_SUCCESS = 1605,
    SIGN_IN_FAILURE = 1606,
    SEND_FILE_SUCCESS = 1603,
};

class Response {
public:
    // Constructor that parses the header and calls parse to process the payload
    Response(const std::vector<uint8_t>& response);

    // Getter functions for header fields
    uint8_t getVersion() const { return version_; }
    uint16_t getResponseCode() const { return responseCode_; }
    uint32_t getPayloadSize() const { return payloadSize_; }
    const std::vector<uint8_t>& getPayload() const {return payload_; }
    std::string Response::getAesKey() const {return std::string(encryptedAESKey_.begin(), encryptedAESKey_.end()); }
    std::string Response::getAESKey() const;


    // Specific parsing functions for different request codes
    void parseSignUpSuccessResponse();
    void parseSignUpFailureResponse();
    void parseSignInResponse();
    void parsePublicKeyReceivedResponse();
    void parseSignInSuceessResponse();
    void parseSignInFailureResponse();
    void parseSendFileSuccessResponse();
    uint32_t getCRCValue() const { return crc_value_; }

private:
    uint8_t version_;               // 1-byte version
    uint16_t responseCode_;          // 2-byte response code
    uint32_t payloadSize_;           // 4-byte payload size
    std::vector<uint8_t> payload_;   // Payload data
    std::vector<uint8_t> encryptedAESKey_; // Encrypted AES key
    // General function to dispatch parsing based on response code
    void parse(uint16_t responseCode);
    uint32_t crc_value_;             // 4-byte CRC value
};


#endif // RESPONSE_HPP
