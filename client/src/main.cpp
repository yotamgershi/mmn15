#include "client.hpp"
#include <string>
#include <chrono>
#include <thread> // Needed for std::this_thread::sleep_for

int main()
{
    std::string host = "localhost";
    std::string port = "1234";
    Client client(host, port);
    client.connect();

    // Input data
    std::string name = "jsnd33";
    std::string clientID = "1234567890";

    // Replace SignUpRequest object with a function call
    std::vector<uint8_t> data = buildSignUpRequest(clientID, name);

    // Send the request to the server
    client.send(data);

    // Simulate some delay
    std::this_thread::sleep_for(std::chrono::seconds(1));

    // Close the connection
    client.close();    

    return 0;
}
