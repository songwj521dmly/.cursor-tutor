#include "Client.h"
#include <iostream>
#include <WS2tcpip.h>
#include <thread>
#include <chrono>
#include <random>  // 添加随机数头文件
#pragma comment(lib, "ws2_32.lib")

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
    std::cout << "\n收到服务器响应: " << response << std::endl;

    size_t pos = response.find('|');
    if (pos == std::string::npos) {
        std::cout << "\n------------------------" << std::endl;
        std::cout << "✗ 服务器响应格式错误" << std::endl;
        std::cout << "------------------------" << std::endl;
        return;
    }

    try {
        int status = std::stoi(response.substr(0, pos));
        std::string message = response.substr(pos + 1);

        std::cout << "\n------------------------" << std::endl;
        switch (status) {
            case static_cast<int>(ResponseStatus::SUCCESS):
                if (message.find("Registration") != std::string::npos) {
                    std::cout << "✓ 注册成功！" << std::endl;
                } else if (message.find("Login successful") != std::string::npos) {
                    std::cout << "✓ 登录成功！" << std::endl;
                    isLoggedIn = true;
                    size_t colonPos = message.find(':');
                    if (colonPos != std::string::npos) {
                        currentUser = message.substr(colonPos + 1);
                    }
                } else if (message.find("Password changed") != std::string::npos) {
                    std::cout << "✓ 密码修改成功！" << std::endl;
                }
                break;
            case static_cast<int>(ResponseStatus::FAILED):
                std::cout << "✗ " << message << std::endl;
                break;
            case static_cast<int>(ResponseStatus::USER_EXISTS):
                std::cout << "✗ 用户已存在！" << std::endl;
                break;
            default:
                std::cout << "未知状态: " << message << std::endl;
        }
        std::cout << "------------------------" << std::endl;
    } catch (const std::exception& e) {
        std::cout << "\n------------------------" << std::endl;
        std::cout << "✗ 解析响应出错: " << e.what() << std::endl;
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
            std::cout << "已通知服务器用户退出: " << currentUser << std::endl;
        } else {
            std::cout << "无法通知服务器用户退出" << std::endl;
        }
    }
}

void Client::showMenu() {
    std::cout << "\n=============================" << std::endl;
    std::cout << "     用户认证系统" << std::endl;
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
                    isLoggedIn = false;
                    currentUser = "";
                    std::cout << "已退出登录" << std::endl;
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
    
    // 创建随机数生成器
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(10, 40);  // 10-40秒的均匀分布
    
    while (running) {
        if (isLoggedIn) {
            if (sendMessage("HEARTBEAT:" + currentUser)) {
                heartbeatCount++;
                std::string response = receiveMessage();
                if (!response.empty()) {
                    size_t pos = response.find('|');
                    if (pos != std::string::npos) {
                        std::string status = response.substr(0, pos);
                        std::string message = response.substr(pos + 1);
                        if (status == "0" && message == "HEARTBEAT_ACK") {
                            auto now = std::chrono::steady_clock::now();
                            auto duration = std::chrono::duration_cast<std::chrono::minutes>(now - lastLogTime).count();
                            std::cout << "\n心跳响应：连接正常 (5分钟内心跳次数: " << heartbeatCount << ")" << std::endl;
                            
                            // 每5分钟重置计数
                            if (duration >= 5) {
                                heartbeatCount = 0;
                                lastLogTime = now;
                            }
                        }
                    }
                }
            }
        }
        
        // 生成随机等待时间（10-40秒）
        int waitTime = dis(gen);
        std::this_thread::sleep_for(std::chrono::seconds(waitTime));
    }
}