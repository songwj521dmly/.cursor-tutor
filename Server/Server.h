#ifndef SERVER_H
#define SERVER_H

#include <winsock2.h>
#include <string>
#include "../Common/UserStruct.h"
#include "../Common/Protocol.h"
#include "UserManager.h"

class Server {
public:
    Server();
    ~Server();
    void start();

private:
    void handleClient(SOCKET clientSocket);
    bool sendMessage(SOCKET clientSocket, const std::string& message);
    std::string receiveMessage(SOCKET clientSocket);
    void processMessage(SOCKET clientSocket, const std::string& message);
    void handleRegister(SOCKET clientSocket, const std::string& message);
    void handleLogin(SOCKET clientSocket, const std::string& message);
    void handleChangePassword(SOCKET clientSocket, const std::string& message);
    void handleLogout(const std::string& message);

    SOCKET serverSocket;
    bool running;
    UserManager userManager;
};

#endif // SERVER_H 