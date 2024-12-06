#ifndef CLIENT_H
#define CLIENT_H

#include <string>
#include <winsock2.h>
#include "../Common/UserStruct.h"
#include "../Common/Protocol.h"
#include <thread>

class Client {
public:
    Client();
    ~Client();
    void start();

private:
    void showMenu();
    void handleRegister();
    void handleLogin();
    void handleChangePassword();
    bool connectToServer();
    bool sendMessage(const std::string& message);
    std::string receiveMessage();
    void handleServerResponse(const std::string& response);
    void sendExitMessage();
    void sendHeartbeat();
    std::thread heartbeatThread;
    bool running;

    SOCKET clientSocket;
    bool isLoggedIn;
    std::string currentUser;
};

#endif // CLIENT_H 