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
    std::string name = "dew3";
    std::string clientID = "1234567890";

    // Sign up
    auto [success, receivedClientID] = client.signUp(clientID, name);
    
    // Simulate some delay
    std::this_thread::sleep_for(std::chrono::seconds(1));

    // Close the connection
    client.close();    

    return 0;
}
