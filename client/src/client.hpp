#ifndef CLIENT_HPP
#define CLIENT_HPP

#include <iostream>
#include <string>
#include <vector>
#include <boost/asio.hpp>

class Client {
public:
    Client(const std::string& host, const std::string& port);
    void connect();
    void send(const std::vector<uint8_t>& data);
    void close();

private:
    boost::asio::io_context io_context_;
    boost::asio::ip::tcp::resolver resolver_;
    boost::asio::ip::tcp::socket socket_;
    std::string host_;
    std::string port_;
};

class Request {
public:
    virtual std::vector<uint8_t> buildRequest() = 0;
    virtual ~Request() = default;

protected:
    std::string clientID_;
    uint8_t version_;
    uint16_t code_;
    uint32_t payloadsize_;
};

class SignUpRequest : public Request {
public:
    SignUpRequest(const std::string& clientID, const std::string& name);
    std::vector<uint8_t> buildRequest() override;

private:
    std::string name_;
};

#endif // CLIENT_HPP
