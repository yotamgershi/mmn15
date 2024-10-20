#include "client.hpp"
#include "RSAWrapper.h"  // Include the RSAPrivateWrapper class
#include <iostream>
#include <fstream>
#include <string>

int main() {
    // Step 1: Read the transfer info from the file (assuming "transfer.info" exists)
    auto [host, port, clientName, filePath] = readTransferInfo("transfer.info"); 

    // Step 2: Initialize the Client object with host, port, client name, and file path
    Client client(host, port, clientName, filePath);

    // Step 3: Connect the client to the server
    client.connect();

    // Step 4: Perform sign-up and receive client ID
    auto [success, receivedClientID] = client.signUp();

    // Step 5: Check if sign-up was successful
    if (!success) {
        std::cerr << "Sign-up failed. Exiting program." << std::endl;
        client.close();
        return 1;  // Exit the program since sign-up failed
    }

    // Step 6: If sign-up was successful, proceed with AES key generation and public key handling
    std::cout << "Sign-up successful. Generating AES key..." << std::endl;

    // Step 7: Generate AES key and save it to priv.key
    client.createAndSaveAESKey();  // This generates, saves the AES key, and stores it

    // Step 8: Generate RSA keys using RSAPrivateWrapper and set the public key in the client
    RSAPrivateWrapper rsaPrivateWrapper;  // Create an instance of RSAPrivateWrapper (this generates the key pair)

    // Get the public key from the private wrapper
    std::string publicKeyStr = rsaPrivateWrapper.getPublicKey();

    if (publicKeyStr.empty()) {
        std::cerr << "Error: RSA public key generation failed." << std::endl;
        client.close();
        return 1;
    }
    std::cout << "Public key generated: " << publicKeyStr << std::endl;

    // Set the public key in the Client object
    client.setPublicKey(publicKeyStr);  // This sets public_key_ in Client

    // Step 9: Send the public key using the public_key_ attribute (no arguments)
    if (client.sendPublicKey()) {
        std::cout << "Public key sent successfully." << std::endl;
    } else {
        std::cerr << "Failed to send the public key." << std::endl;
    }

    // Step 10: Close the connection after tasks are complete    
    client.close();

    return 0;
}
