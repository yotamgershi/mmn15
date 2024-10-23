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

    std::cout << "Host: " << host << std::endl;
    std::cout << "Port: " << port << std::endl;
    std::cout << "Client Name: " << clientName << std::endl;
    std::cout << "File Path: " << filePath << std::endl;

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

    std::vector<std::string> lines;
    std::string line;

    // Read all lines from the file
    while (std::getline(infile, line)) {
        lines.push_back(line);
    }

    // Close the file after reading
    infile.close();

    // Check if the file has at least two lines to modify
    if (lines.size() >= 2) {
        // Convert the second row to an integer and increment it
        try {
            int number = std::stoi(lines[1]);
            number += 1;

            // Update the second row with the incremented value
            lines[1] = std::to_string(number);
        } catch (const std::invalid_argument& e) {
            std::cerr << "Error: The second row is not a valid number." << std::endl;
            return;
        } catch (const std::out_of_range& e) {
            std::cerr << "Error: The number in the second row is out of range." << std::endl;
            return;
        }
    } else {
        std::cerr << "Error: File does not have enough lines." << std::endl;
        return;
    }

    // Reopen the file for writing (truncating the file)
    std::ofstream outfile(filename, std::ios::trunc);
    if (!outfile.is_open()) {
        std::cerr << "Error opening file for writing: " << filename << std::endl;
        return;
    }

    // Write all lines back to the file
    for (const auto& l : lines) {
        outfile << l << std::endl;
    }

    // Close the file after writing
    outfile.close();
}
