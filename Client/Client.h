#ifndef CLIENT_H
#define CLIENT_H

#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <thread>
#include <chrono>
#include <limits>
#include <iostream>
#include "../Common/Protocol.h"
#include "../Common/UserStruct.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

class Client {
public:
    Client();
    ~Client();
    void start();

private:
    void handleServerResponse(const std::string& response);
    bool connectToServer();
    bool sendMessage(const std::string& message);
    std::string receiveMessage();
    void sendHeartbeat();
    void showLoggedInMenu();
    void changePassword();
    void logout();
    
    void showMenu();
    void sendExitMessage();
    void handleRegister();
    void handleLogin();
    void handleChangePassword();
    bool checkHeartbeatTimeout();

    SOCKET clientSocket;
    bool running;
    bool isLoggedIn;
    std::string currentUser;
    std::thread heartbeatThread;
    std::chrono::steady_clock::time_point lastHeartbeatResponse;
};

#endif // CLIENT_H 