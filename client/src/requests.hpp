#ifndef REQUEST_HPP
#define REQUEST_HPP

#include <vector>
#include <string>
#include <stdexcept>  // For std::runtime_error

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
    // Constructor builds the header (Client ID, Version, Request Code)
    Request(const std::string& clientID, uint8_t version, uint16_t requestCode = 826);

    // Function to build the sign-up request by adding payload and updating payload size
    void buildSignUpRequest(const std::string& name);

    // Function to build the sendPublicKey request by adding the public key and updating payload size
    void buildSendPublicKey(const std::string& name, const std::string& publicKey);

    // Function to return the full request (header + payload)
    std::vector<uint8_t> getRequest() const;

private:
    std::string clientID_;          // 16-byte Client ID
    uint8_t version_;               // 1-byte version
    uint16_t requestCode_;          // 2-byte request code
    uint32_t payloadSize_;          // 4-byte payload size (updated when payload is added)
    std::vector<uint8_t> payload_;  // Payload data (e.g., name, public key)
    std::vector<uint8_t> request_;  // Full request (header + payload)
};


#endif // REQUEST_HPP
