#include "Client.h"
#include <iostream>
#include <sstream>
#include <random>
#include "../Common/Protocol.h"
#include "../Common/UserStruct.h"

Client::Client() : clientSocket(INVALID_SOCKET), isLoggedIn(false), running(true) {
    // 初始化 Winsock
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        std::cerr << "WSAStartup failed: " << result << std::endl;
    }
}

Client::~Client() {
    running = false;  // 停止心跳线程
    if (heartbeatThread.joinable()) {
        heartbeatThread.join();
    }
    sendExitMessage();
    if (clientSocket != INVALID_SOCKET) {
        closesocket(clientSocket);
    }
    WSACleanup();
}

bool Client::connectToServer() {
    clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientSocket == INVALID_SOCKET) {
        std::cerr << "Socket creation failed" << std::endl;
        return false;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(8888);
    inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr);

    if (connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Connection failed" << std::endl;
        closesocket(clientSocket);
        clientSocket = INVALID_SOCKET;
        return false;
    }

    return true;
}

bool Client::sendMessage(const std::string& message) {
    if (clientSocket == INVALID_SOCKET) {
        return false;
    }

    int result = send(clientSocket, message.c_str(), message.length(), 0);
    return result != SOCKET_ERROR;
}

std::string Client::receiveMessage() {
    char buffer[1024];
    int bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    
    if (bytesReceived > 0) {
        buffer[bytesReceived] = '\0';
        return std::string(buffer);
    }
    
    return "";
}

void Client::handleServerResponse(const std::string& response) {
    size_t pos = response.find('|');
    if (pos != std::string::npos) {
        std::string status = response.substr(0, pos);
        std::string message = response.substr(pos + 1);
        
        std::cout << "\n------------------------" << std::endl;
        if (status == "3") {  // FORCE_LOGOUT，优先处理强制下线
            std::cout << "! " << message << std::endl;
            std::cout << "------------------------" << std::endl;
            std::cout << "\n您已被强制下线，请重新登录！" << std::endl;
            isLoggedIn = false;
            currentUser = "";
            running = false;  // 停止心跳线程
            return;  // 直接返回，不再处理其他响应
        }
        else if (status == "0") {  // SUCCESS
            std::cout << "✓ ";
            if (message.find("Login successful") != std::string::npos) {
                size_t colonPos = message.find(':');
                if (colonPos != std::string::npos) {
                    currentUser = message.substr(colonPos + 1);
                    isLoggedIn = true;
                    std::cout << "登录成功！" << std::endl;
                    std::cout << "------------------------" << std::endl;
                    std::cout << "\n欢迎回来，" << currentUser << "！" << std::endl;
                    showLoggedInMenu();
                }
            }
            else {
                std::cout << message << std::endl;
            }
        }
        else {
            std::cout << "? " << message << std::endl;
        }
        std::cout << "------------------------" << std::endl;
    }
}

void Client::handleRegister() {
    UserInfo userInfo;
    
    std::cout << "\n====== 用户注册 ======" << std::endl;
    std::cout << "请输入用户名: ";
    std::getline(std::cin, userInfo.username);
    
    std::cout << "请输入密码: ";
    std::getline(std::cin, userInfo.password);
    
    std::cout << "请输入邮箱: ";
    std::getline(std::cin, userInfo.email);
    
    std::cout << "请输入设备信息: ";
    std::getline(std::cin, userInfo.deviceInfo);

    std::string message = "REGISTER:" + Protocol::serializeUserInfo(userInfo);
    if (sendMessage(message)) {
        std::string response = receiveMessage();
        if (!response.empty()) {
            handleServerResponse(response);
        } else {
            std::cout << "\n------------------------" << std::endl;
            std::cout << "✗ 未收到服务器响应" << std::endl;
            std::cout << "------------------------" << std::endl;
        }
    }
}

void Client::handleLogin() {
    std::string username, password;
    
    std::cout << "\n====== 用户登录 ======" << std::endl;
    std::cout << "请输入用户名: ";
    std::getline(std::cin, username);
    
    std::cout << "请输入密码: ";
    std::getline(std::cin, password);

    std::string message = "LOGIN:" + username + "|" + password;
    if (sendMessage(message)) {
        std::string response = receiveMessage();
        if (!response.empty()) {
            handleServerResponse(response);
            if (isLoggedIn) {
                std::cout << "\n欢迎回来，" << currentUser << "！" << std::endl;
            }
        } else {
            std::cout << "\n------------------------" << std::endl;
            std::cout << "✗ 未收到服务器响应" << std::endl;
            std::cout << "------------------------" << std::endl;
        }
    }
}

void Client::handleChangePassword() {
    std::string oldPassword, newPassword;
    
    std::cout << "\n====== 修改密码 ======" << std::endl;
    std::cout << "请输入旧密码: ";
    std::getline(std::cin, oldPassword);
    
    std::cout << "请输入新密码: ";
    std::getline(std::cin, newPassword);

    std::string message = "CHANGE_PASSWORD:" + currentUser + "|" + oldPassword + "|" + newPassword;
    if (sendMessage(message)) {
        std::string response = receiveMessage();
        if (!response.empty()) {
            handleServerResponse(response);
        } else {
            std::cout << "\n------------------------" << std::endl;
            std::cout << "✗ 未收到服务器响应" << std::endl;
            std::cout << "------------------------" << std::endl;
        }
    }
}

void Client::sendExitMessage() {
    if (isLoggedIn) {
        std::string message = "LOGOUT:" + currentUser;
        if (sendMessage(message)) {
            std::cout << "已通知服务用户退出: " << currentUser << std::endl;
        } else {
            std::cout << "无法通知服务器用户退出" << std::endl;
        }
    }
}

void Client::showMenu() {
    std::cout << "\n=============================" << std::endl;
    std::cout << "     户认证系统" << std::endl;
    std::cout << "=============================" << std::endl;
    
    if (!isLoggedIn) {
        std::cout << "1. 用户注册" << std::endl;
        std::cout << "2. 用户登录" << std::endl;
        std::cout << "3. 退出系统" << std::endl;
    } else {
        std::cout << "当前用户: " << currentUser << std::endl;
        std::cout << "1. 修改密码" << std::endl;
        std::cout << "2. 退出登录" << std::endl;
        std::cout << "3. 退出系统" << std::endl;
    }
    
    std::cout << "=============================" << std::endl;
}

void Client::start() {
    if (!connectToServer()) {
        std::cerr << "Failed to connect to server" << std::endl;
        return;
    }

    // 启动心跳线程
    heartbeatThread = std::thread(&Client::sendHeartbeat, this);

    while (true) {
        showMenu();
        int choice;
        std::cout << "请选择操作: ";
        std::cin >> choice;
        std::cin.clear();
        std::cin.ignore(1000, '\n');

        if (!isLoggedIn) {  // 未登录状态的选项处理
            switch (choice) {
                case 1:
                    handleRegister();
                    break;
                case 2:
                    handleLogin();
                    break;
                case 3:
                    sendExitMessage();
                    std::cout << "退出程序" << std::endl;
                    return;
                default:
                    std::cout << "无效的选择，请重试" << std::endl;
                    break;
            }
        } else {  // 已登录状态的选项处理
            switch (choice) {
                case 1:
                    handleChangePassword();
                    break;
                case 2:
                    logout();
                    break;
                case 3:
                    sendExitMessage();
                    std::cout << "退出程序" << std::endl;
                    return;
                default:
                    std::cout << "无效的选择，请重试" << std::endl;
                    break;
            }
        }
    }
}



void Client::sendHeartbeat() {
    int heartbeatCount = 0;
    auto lastLogTime = std::chrono::steady_clock::now();
    lastHeartbeatResponse = std::chrono::steady_clock::now();
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(10, 40);
    
    while (running) {
        if (isLoggedIn) {
            if (sendMessage("HEARTBEAT:" + currentUser)) {
                std::string response = receiveMessage();
                if (!response.empty()) {
                    lastHeartbeatResponse = std::chrono::steady_clock::now();
                    handleServerResponse(response);
                    if (!isLoggedIn) {
                        break;
                    }
                }
            }
            
            // 检查心跳超时
            auto now = std::chrono::steady_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - lastHeartbeatResponse).count();
            if (duration > 2) {  // 2秒超时
                std::cout << "\n------------------------" << std::endl;
                std::cout << "! 服务器心跳响应超时" << std::endl;
                std::cout << "------------------------" << std::endl;
                std::cout << "\n与服务器的连接已断开，请重新登录！" << std::endl;
                isLoggedIn = false;
                currentUser = "";
                running = false;
                break;
            }
        }
        
        int waitTime = dis(gen);
        std::this_thread::sleep_for(std::chrono::seconds(waitTime));
    }
}

bool Client::checkHeartbeatTimeout() {
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - lastHeartbeatResponse).count();
    return duration <= 22;  // 改为22秒超时
}

void Client::showLoggedInMenu() {
    while (isLoggedIn) {  // 检查登录状态
        std::cout << "\n=============================" << std::endl;
        std::cout << "     用户认证系统" << std::endl;
        std::cout << "=============================" << std::endl;
        std::cout << "当前用户: " << currentUser << std::endl;
        std::cout << "1. 修改密码" << std::endl;
        std::cout << "2. 退出登录" << std::endl;
        std::cout << "3. 退出系统" << std::endl;
        std::cout << "=============================" << std::endl;
        std::cout << "请选择操作: ";

        int choice;
        std::cin >> choice;
        std::cin.ignore(1000, '\n');

        if (!isLoggedIn) {  // 在处理选择前再次检查登录状态
            start();  // 如果已经被强制下线，返回主菜单
            return;
        }

        switch (choice) {
            case 1:
                changePassword();
                if (!isLoggedIn) return;  // 如果在修改密码过程中被强制下线
                break;
            case 2:
                logout();
                return;
            case 3:
                logout();
                exit(0);
            default:
                std::cout << "无效的选择，请重试" << std::endl;
        }
    }
}

void Client::logout() {
    if (isLoggedIn) {
        if (sendMessage("LOGOUT:" + currentUser)) {
            std::cout << "\n已成功退出登录" << std::endl;
        }
        isLoggedIn = false;
        currentUser = "";
    }
}

void Client::changePassword() {
    if (!isLoggedIn) {  // 检查登录状态
        std::cout << "\n您需要先登录才能修改密码" << std::endl;
        return;
    }

    std::cout << "\n====== 修改密码 ======" << std::endl;
    std::cout << "请输入旧密码: ";
    std::string oldPassword;
    std::getline(std::cin, oldPassword);

    std::cout << "请输入新密码: ";
    std::string newPassword;
    std::getline(std::cin, newPassword);

    std::string message = "CHANGE_PASSWORD:" + currentUser + "|" + oldPassword + "|" + newPassword;
    if (sendMessage(message)) {
        std::string response = receiveMessage();
        handleServerResponse(response);
        if (!isLoggedIn) {  // 如果在修改密码过程中被强制下线
            start();  // 重新启动客户端，返回主菜单
        }
    }
}