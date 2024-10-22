#ifndef REQUEST_HPP
#define REQUEST_HPP

#include <vector>
#include <string>
#include <stdexcept>
#include <map>

enum RequestCode {
    SIGN_UP = 825,
    SEND_PUBLIC_KEY = 826,
    SIGN_IN = 827,
    SEND_FILE = 828,
    CRC_VALID = 900,
    CRC_INVALID = 901,
    CRC_INVALID_4TH_TIME = 902
};

class Request {
public:
    // Constructor that parses the request code and builds the appropriate request
    Request(const std::string& clientID, uint8_t version, uint16_t requestCode, const std::string& name, const std::string& publicKey = "");

    // Function to return the full request (header + payload)
    std::vector<uint8_t> getRequest() const { return request_; }

private:
    std::string clientID_;          // 16-byte Client ID
    uint8_t version_;               // 1-byte version
    uint16_t requestCode_;          // 2-byte request code
    uint32_t payloadSize_;          // 4-byte payload size
    std::vector<uint8_t> payload_;  // Payload data
    std::vector<uint8_t> request_;  // Full request (header + payload)

    // Function to dispatch the appropriate request-building function
    void buildRequest(uint16_t requestCode, const std::string& name, const std::string& publicKey);

    // Request-building functions
    void buildSignUpRequest(const std::string& name);
    void buildSendPublicKeyRequest(const std::string& name, const std::string& publicKey);
    void buildSignInRequest(std::string name);
    void buildSendFileRequest(const std::string& name);
};

#endif // REQUEST_HPP
