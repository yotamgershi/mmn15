#ifndef RESPONSE_HPP
#define RESPONSE_HPP

#include <vector>
#include <string>
#include <stdexcept>  // For std::runtime_error

enum ResponseCodes {
    SIGN_UP_SUCCESS = 1600,
    SIGN_UP_FAILURE = 1601,
};

class Response {
public:
    // Constructor that parses the header and calls parse to process the payload
    Response(const std::vector<uint8_t>& response);

    // Getter functions for header fields
    uint8_t getVersion() const { return version_; }
    uint16_t getResponseCode() const { return responseCode_; }
    uint32_t getPayloadSize() const { return payloadSize_; }
    const std::vector<uint8_t>& getPayload() const { return payload_; }

    // Specific parsing functions for different request codes
    void parseSignUpSuccessResponse();
    void parseSignUpFailureResponse();
    void parseSendPublicKeyResponse();
    void parseSignInResponse();

private:
    uint8_t version_;               // 1-byte version
    uint16_t responseCode_;          // 2-byte response code
    uint32_t payloadSize_;           // 4-byte payload size
    std::vector<uint8_t> payload_;   // Payload data

    // General function to dispatch parsing based on response code
    void parse(uint16_t responseCode);
};


#endif // RESPONSE_HPP
