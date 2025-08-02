// Client.cpp
#include "Client.h"
#include <iostream>
#include <fstream>
#include <sstream>

Client::Client() {
    readServerInfo();
}

void Client::run() {
    if (checkIfRegistered()) {
        std::cout << "You are already registered. Cannot register again.\n";
    }

    while (true) {
        showMenu();
        int choice;
        std::cin >> choice;
        if (choice == 0) {
            std::cout << "Exiting client...\n";
            break;
        }
        handleChoice(choice);
    }
}

// Reads server IP and port from server.info
void Client::readServerInfo() {
    std::ifstream file("server.info");
    if (!file) {
        std::cerr << "server.info not found." << std::endl;
        exit(1);
    }
    std::string line;
    std::getline(file, line);
    size_t colon = line.find(':');
    serverAddress = line.substr(0, colon);
    serverPort = std::stoi(line.substr(colon + 1));
}

// Checks if the user has already registered by verifying the existence of me.info
bool Client::checkIfRegistered() {
    std::ifstream f("me.info");
    return f.good();
}

// Displays the main client menu
void Client::showMenu() {
    std::cout <<
              "\nMessageU client at your service.\n"
              "110) Register\n"
              "120) Request for clients list\n"
              "130) Request for public key\n"
              "140) Request for waiting messages\n"
              "150) Send a text message\n"
              "151) Send a request for symmetric key\n"
              "152) Send your symmetric key\n"
              "0) Exit client\n"
              "? ";
}

// Handles user's menu selection
void Client::handleChoice(int choice) {
    switch (choice) {
        case 110:
            registerUser();
            break;
        case 120:
            requestClientsList();
            break;
        case 130:
            requestPublicKey();
            break;
        case 140:
            requestWaitingMessages();
            break;
        case 150:
            sendTextMessage();
            break;
        case 151:
            requestSymmetricKey();
            break;
        case 152:
            sendSymmetricKey();
            break;
        default:
            std::cout << "Invalid choice\n";
            break;
    }
}

// Registration logic to be implemented
void Client::registerUser() {
    std::cout << "Registration selected.\n";
    // TODO: implement user registration
}

void Client::requestClientsList() {
    std::cout << "Clients list requested.\n";
    // TODO: implement
}

void Client::requestPublicKey() {
    std::cout << "Public key request selected.\n";
    // TODO: implement
}

void Client::requestWaitingMessages() {
    std::cout << "Waiting messages requested.\n";
    // TODO: implement
}

void Client::sendTextMessage() {
    std::cout << "Send text message selected.\n";
    // TODO: implement
}

void Client::requestSymmetricKey() {
    std::cout << "Request symmetric key selected.\n";
    // TODO: implement
}

void Client::sendSymmetricKey() {
    std::cout << "Send symmetric key selected.\n";
    // TODO: implement
}
