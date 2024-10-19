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

// Function to build a sign-up request
std::vector<uint8_t> buildSignUpRequest(const std::string& clientID, const std::string& name);

#endif // CLIENT_HPP
