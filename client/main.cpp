// main.cpp
#include <iostream>
#include "ConfigParser.h"
#include "Connection.h"
#include "CryptoManager.h"
#include "Client.h"

int main() {
    // 1. Read configuration files
    ConfigParser cfg("server.info", "my.info");
    auto [serverIp, serverPort] = cfg.getServerAddress();
    auto [clientName, clientId, privateKey] = cfg.getClientInfo();

    // 2. Establish connection to the server
    Connection connection(serverIp, serverPort);

    // 3. Initialize the cryptography manager
    CryptoManager cryptoManager(privateKey);

    // 4. Create the Client object and run the main loop
    Client client(connection, cryptoManager, clientName, clientId);
    client.run();  // Starts the menu and handles commands

    return 0;
}
