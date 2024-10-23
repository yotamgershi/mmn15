#include "client.hpp"
#include "RSAWrapper.h"  // Include the RSAPrivateWrapper class
#include <iostream>
#include <fstream>
#include <string>

void incrementSecondRowNumber(const std::string& filename);

int main() {
    // Increment second row number for debugging purposes
    incrementSecondRowNumber("transfer.info");

    // Step 1: Read the transfer info from the file (assuming "transfer.info" exists)
    auto [host, port, clientName, filePath] = readTransferInfo("transfer.info"); 

    // Step 2: Initialize the Client object with host, port, client name, and file path
    Client client(host, port, clientName, filePath);

    // Step 3: Connect the client to the server
    client.connect();

    // Step 4: Check if the "me.info" file exists to decide whether to sign up or sign in
    if (!fileExists("me.info")) {
        // Sign-up flow
        std::cout << "No existing client info found, proceeding with sign-up..." << std::endl;

        auto [success, receivedClientID] = client.signUp();

        if (!success) {
            std::cerr << "Sign-up failed. Exiting program." << std::endl;
            client.close();
            return 1;  // Exit the program since sign-up failed
        }

        std::cout << "Sign-up successful. Generating AES key..." << std::endl;

        // Generate AES key and save it to priv.key
        client.createAndSaveAESKey();

        // Generate RSA keys using RSAPrivateWrapper and set the public key in the client
        RSAPrivateWrapper rsaPrivateWrapper;
        std::string publicKeyStr = rsaPrivateWrapper.getPublicKey();

        if (publicKeyStr.empty()) {
            std::cerr << "Error: RSA public key generation failed." << std::endl;
            client.close();
            return 1;
        }

        std::cout << "Public key generated: " << publicKeyStr << std::endl;
        client.setPublicKey(publicKeyStr);

        // Send the public key
        if (client.sendPublicKey()) {
            std::cout << "Public key sent successfully." << std::endl;
        } else {
            std::cerr << "Failed to send the public key." << std::endl;
        }
    } else {
        // Sign-in flow
        std::cout << "Existing client info found, proceeding with sign-in..." << std::endl;

        if (client.signIn()) {
            std::cout << "Sign-in successful." << std::endl;
        } else {
            std::cerr << "Sign-in failed." << std::endl;
            client.close();
            return 1;
        }
    }

    // Step 5: Send file (regardless of sign-up or sign-in)
    std::cout << "Now trying to send the file: " << filePath << std::endl;
    client.sendFile(filePath);

    // Step 6: Close the connection after tasks are complete
    client.close();

    return 0;
}


void incrementSecondRowNumber(const std::string& filename) {
    std::ifstream infile(filename);
    if (!infile.is_open()) {
        std::cerr << "Error opening file: " << filename << std::endl;
        return;
    }

    std::string firstRow, secondRow;
    
    // Read the first two rows
    std::getline(infile, firstRow);
    std::getline(infile, secondRow);

    // Close the file after reading
    infile.close();

    // Convert the second row to an integer and increment it
    int number = std::stoi(secondRow);
    number += 1;

    // Reopen the file for writing
    std::ofstream outfile(filename);
    if (!outfile.is_open()) {
        std::cerr << "Error opening file for writing: " << filename << std::endl;
        return;
    }

    // Write the first row back and the incremented second row
    outfile << firstRow << std::endl;
    outfile << number << std::endl;

    // Close the file after writing
    outfile.close();
}
