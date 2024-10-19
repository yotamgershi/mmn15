#ifndef REQUESTS_HPP
#define REQUESTS_HPP

#include <iostream>
#include <string>
#include <vector>


class Request {
public:
    Request(const std::string& ClientID_, uint8_t version_, uint16_t requestCode_, uint32_t payloadSize_, const std::vector<uint8_t>& payload_);
    std::vector<uint8_t> buildSignUpRequest(const std::string& name);
    std::vector<uint8_t> buildSendPublicKey(const std::string& publicKey) const;
    std::vector<uint8_t> serialize() const;

private:
    std::string ClientID_;        // Client ID (16 bytes)
    uint8_t version_;             // Version (1 byte)
    uint16_t requestCode_;        // Request code (2 bytes)
    uint32_t payloadSize_;        // Payload size (4 bytes)
    std::vector<uint8_t> payload_;  // Payload (variable size)
};

#endif // REQUESTS_HPP