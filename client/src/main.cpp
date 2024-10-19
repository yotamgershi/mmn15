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
    
    // If sign-up was successful, generate RSA key pair and send public key
    if (success) {
        auto [publicKeyStr, privateKeyStr] = client.generateRSAKeyPair();
        client.sendPublicKey(publicKeyStr);
    }

    // Close the connection
    client.close();    

    return 0;
}
