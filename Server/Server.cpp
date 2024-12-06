#include "Server.h"
#include <iostream>
#include <WS2tcpip.h>
#include <chrono>
#include <iomanip>
#pragma comment(lib, "ws2_32.lib")

Server::Server() : serverSocket(INVALID_SOCKET), running(false) {
    // 初始化 Winsock
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        std::cerr << "WSAStartup failed: " << result << std::endl;
        return;
    }
}

Server::~Server() {
    if (serverSocket != INVALID_SOCKET) {
        closesocket(serverSocket);
        serverSocket = INVALID_SOCKET;
    }
    WSACleanup();
}

void Server::start() {
    serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "Error creating socket" << std::endl;
        return;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(8888);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Bind failed" << std::endl;
        closesocket(serverSocket);
        return;
    }

    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Listen failed" << std::endl;
        closesocket(serverSocket);
        return;
    }

    std::cout << "Server is running on port 8888..." << std::endl;
    running = true;

    while (running) {
        SOCKET clientSocket = accept(serverSocket, nullptr, nullptr);
        if (clientSocket == INVALID_SOCKET) {
            std::cerr << "Accept failed" << std::endl;
            continue;
        }

        std::cout << "New client connected" << std::endl;
        handleClient(clientSocket);
    }
}

void Server::handleClient(SOCKET clientSocket) {
    while (true) {
        std::string message = receiveMessage(clientSocket);
        if (message.empty()) {
            std::cout << "客户端断开连接" << std::endl;
            break;
        }
        processMessage(clientSocket, message);
    }
    closesocket(clientSocket);
    std::cout << "客户端连接已关闭" << std::endl;
}

bool Server::sendMessage(SOCKET clientSocket, const std::string& message) {
    int result = send(clientSocket, message.c_str(), message.length(), 0);
    return result != SOCKET_ERROR;
}

std::string Server::receiveMessage(SOCKET clientSocket) {
    char buffer[1024];
    int bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    
    if (bytesReceived > 0) {
        buffer[bytesReceived] = '\0';
        return std::string(buffer);
    }
    
    return "";
}

void Server::processMessage(SOCKET clientSocket, const std::string& message) {
    size_t colonPos = message.find(':');
    if (colonPos == std::string::npos) {
        sendMessage(clientSocket, Protocol::createResponse(ResponseStatus::FAILED, "Invalid message format"));
        return;
    }

    std::string command = message.substr(0, colonPos);
    std::string data = message.substr(colonPos + 1);

    if (command == "REGISTER") {
        handleRegister(clientSocket, data);
    }
    else if (command == "LOGIN") {
        handleLogin(clientSocket, data);
    }
    else if (command == "CHANGE_PASSWORD") {
        handleChangePassword(clientSocket, data);
    }
    else if (command == "LOGOUT") {
        handleLogout(data);
    }
    else if (command == "HEARTBEAT") {
        auto now = std::chrono::system_clock::now();
        std::time_t now_c = std::chrono::system_clock::to_time_t(now);
        
        std::tm now_tm;
        localtime_s(&now_tm, &now_c);

        std::cout << "\n收到心跳消息：" << data 
                  << " (时间: " << std::put_time(&now_tm, "%Y-%m-%d %H:%M:%S") << ")" << std::endl;
        userManager.updateUserStatus(data, true);
        sendMessage(clientSocket, Protocol::createResponse(ResponseStatus::SUCCESS, "HEARTBEAT_ACK"));
    }
    else {
        sendMessage(clientSocket, Protocol::createResponse(ResponseStatus::FAILED, "Unknown command"));
    }
}

void Server::handleRegister(SOCKET clientSocket, const std::string& message) {
    UserInfo userInfo;
    if (!Protocol::parseUserInfo(message, userInfo)) {
        std::cout << "注册失败：无效的用户信息格式" << std::endl;
        sendMessage(clientSocket, Protocol::createResponse(ResponseStatus::FAILED, "Invalid user info format"));
        return;
    }

    std::cout << "\n收到注册请求：" << std::endl;
    std::cout << "- 用户名：" << userInfo.username << std::endl;
    std::cout << "- 邮箱：" << userInfo.email << std::endl;
    std::cout << "- 设备信息：" << userInfo.deviceInfo << std::endl;

    if (userManager.registerUser(userInfo)) {
        std::cout << "注册成功！" << std::endl;
        sendMessage(clientSocket, Protocol::createResponse(ResponseStatus::SUCCESS, "Registration successful"));
    }
    else {
        std::cout << "注册失败：用户已存���" << std::endl;
        sendMessage(clientSocket, Protocol::createResponse(ResponseStatus::USER_EXISTS, "User already exists"));
    }
}

void Server::handleLogin(SOCKET clientSocket, const std::string& message) {
    size_t pos = message.find('|');
    if (pos == std::string::npos) {
        std::cout << "登录失败：无效的登录格式" << std::endl;
        sendMessage(clientSocket, Protocol::createResponse(ResponseStatus::FAILED, "Invalid login format"));
        return;
    }

    std::string username = message.substr(0, pos);
    std::string password = message.substr(pos + 1);

    std::cout << "\n收到登录请求：" << std::endl;
    std::cout << "- 用户名：" << username << std::endl;

    if (userManager.loginUser(username, password)) {
        std::cout << "登录成功！" << std::endl;
        sendMessage(clientSocket, Protocol::createResponse(ResponseStatus::SUCCESS, "Login successful:" + username));
    }
    else {
        std::cout << "登录失败：用户名或密码错误" << std::endl;
        sendMessage(clientSocket, Protocol::createResponse(ResponseStatus::FAILED, "Invalid username or password"));
    }
}

void Server::handleChangePassword(SOCKET clientSocket, const std::string& message) {
    size_t pos1 = message.find('|');
    size_t pos2 = message.find('|', pos1 + 1);
    if (pos1 == std::string::npos || pos2 == std::string::npos) {
        std::cout << "修改密码失败：无效的格式" << std::endl;
        sendMessage(clientSocket, Protocol::createResponse(ResponseStatus::FAILED, "Invalid change password format"));
        return;
    }

    std::string username = message.substr(0, pos1);
    std::string oldPassword = message.substr(pos1 + 1, pos2 - pos1 - 1);
    std::string newPassword = message.substr(pos2 + 1);

    std::cout << "\n收到修改密码请求：" << std::endl;
    std::cout << "- 用户名：" << username << std::endl;

    if (userManager.changePassword(username, oldPassword, newPassword)) {
        std::cout << "密码修改成功！" << std::endl;
        sendMessage(clientSocket, Protocol::createResponse(ResponseStatus::SUCCESS, "Password changed successfully"));
    }
    else {
        std::cout << "密码修改失败" << std::endl;
        sendMessage(clientSocket, Protocol::createResponse(ResponseStatus::FAILED, "Failed to change password"));
    }
}

void Server::handleLogout(const std::string& username) {
    std::cout << "\n用户登出：" << username << std::endl;
} 