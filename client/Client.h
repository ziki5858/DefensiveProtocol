#pragma once
#include <string>

class Client {
public:
    Client();
    void run();

private:
    std::string serverAddress;
    int serverPort;

    // Reads server IP and port from server.info
    void readServerInfo();

    // Checks if the user is already registered (me.info exists)
    bool checkIfRegistered();

    // Displays the main menu
    void showMenu();

    // Handles the user's menu selection
    void handleChoice(int choice);

    // Menu option handlers
    void registerUser();
    void requestClientsList();
    void requestPublicKey();
    void requestWaitingMessages();
    void sendTextMessage();
    void requestSymmetricKey();
    void sendSymmetricKey();
};
