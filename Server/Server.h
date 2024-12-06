#ifndef SERVER_H
#define SERVER_H

#include <winsock2.h>
#include <string>
#include <thread>
#include "../Common/UserStruct.h"
#include "../Common/Protocol.h"
#include "UserManager.h"
#include <unordered_map>

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
    void checkHeartbeatTimeouts();
    void forceLogout(const std::string& username);

    SOCKET serverSocket;
    bool running;
    UserManager userManager;
    std::thread timeoutCheckerThread;
    std::unordered_map<std::string, SOCKET> userSockets;
};

#endif // SERVER_H 