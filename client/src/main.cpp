#include "client.hpp"
#include <iostream>
#include <fstream>
#include <string>
#include <chrono>
#include <thread>

int main()
{
    auto [host, port, clientName, filePath] = readTransferInfo("transfer.info"); 

    Client client(host, port, clientName, filePath);
    client.connect();

    // Sign up
    auto [success, receivedClientID] = client.signUp();
    
    // Simulate some delay
    std::this_thread::sleep_for(std::chrono::seconds(1));

    // Close the connection
    client.close();    

    return 0;
}
