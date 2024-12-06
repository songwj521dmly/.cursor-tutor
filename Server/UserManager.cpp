#include "UserManager.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>

UserManager::UserManager() {
    loadUsersFromFile();
}

UserManager::~UserManager() {
    saveUsersToFile();
}

bool UserManager::registerUser(const UserInfo& userInfo) {
    if (users.find(userInfo.username) != users.end()) {
        return false;
    }

    UserInfo newUser = userInfo;
    newUser.password = encryptPassword(userInfo.password);
    newUser.isDisabled = false;
    newUser.lastHeartbeat = std::chrono::system_clock::now();

    users[newUser.username] = newUser;
    saveUsersToFile();
    return true;
}

bool UserManager::loginUser(const std::string& username, const std::string& password) {
    auto it = users.find(username);
    if (it == users.end()) {
        return false;
    }

    UserInfo& user = it->second;
    if (user.isDisabled) {
        return false;
    }

    if (!verifyPassword(password, user.password)) {
        return false;
    }

    user.isOnline = true;
    user.lastHeartbeat = std::chrono::system_clock::now();
    return true;
}

bool UserManager::changePassword(const std::string& username, const std::string& oldPassword, const std::string& newPassword) {
    auto it = users.find(username);
    if (it == users.end()) {
        return false;
    }

    UserInfo& user = it->second;
    if (user.isDisabled) {
        return false;
    }

    if (!verifyPassword(oldPassword, user.password)) {
        return false;
    }

    user.password = encryptPassword(newPassword);
    user.lastHeartbeat = std::chrono::system_clock::now();
    saveUsersToFile();
    return true;
}

void UserManager::updateUserStatus(const std::string& username, bool isOnline) {
    auto it = users.find(username);
    if (it != users.end()) {
        it->second.isOnline = isOnline;
        if (isOnline) {
            it->second.lastHeartbeat = std::chrono::system_clock::now();
        }
    }
}

bool UserManager::verifyPassword(const std::string& inputPassword, const std::string& storedPassword) {
    return encryptPassword(inputPassword) == storedPassword;
}

std::string UserManager::encryptPassword(const std::string& password) {
    std::string encrypted = password;
    for (char& c : encrypted) {
        c = c + 1;
    }
    return encrypted;
}

void UserManager::loadUsersFromFile() {
    std::ifstream file("users.txt");
    if (!file.is_open()) {
        std::cerr << "无法打开用户数据文件" << std::endl;
        return;
    }

    std::string line;
    while (std::getline(file, line)) {
        std::istringstream stream(line);
        UserInfo user;
        std::string lastHeartbeatStr;
        if (std::getline(stream, user.username, '|') &&
            std::getline(stream, user.password, '|') &&
            std::getline(stream, user.email, '|') &&
            std::getline(stream, user.deviceInfo, '|') &&
            std::getline(stream, lastHeartbeatStr, '|')) {
            user.lastHeartbeat = std::chrono::system_clock::time_point(std::chrono::milliseconds(std::stoll(lastHeartbeatStr)));
            users[user.username] = user;
        }
    }
    file.close();
}

void UserManager::saveUsersToFile() {
    std::ofstream file("users.txt");
    if (!file.is_open()) {
        std::cerr << "无法打开用户数据文件" << std::endl;
        return;
    }

    for (const auto& pair : users) {
        const UserInfo& user = pair.second;
        file << user.username << '|'
             << user.password << '|'
             << user.email << '|'
             << user.deviceInfo << '|'
             << std::chrono::duration_cast<std::chrono::milliseconds>(user.lastHeartbeat.time_since_epoch()).count()
             << '\n';
    }
    file.close();
}

std::vector<std::string> UserManager::checkTimeouts(int timeoutSeconds) {
    std::vector<std::string> timeoutUsers;
    auto now = std::chrono::system_clock::now();
    
    for (const auto& pair : users) {
        const auto& username = pair.first;
        const auto& user = pair.second;
        
        if (user.isOnline) {
            auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - user.lastHeartbeat).count();
            if (duration > timeoutSeconds) {
                std::cout << "用户 " << username << " 超时检测: "
                          << duration << " 秒 (超时阈值: " << timeoutSeconds << " 秒)" << std::endl;
                timeoutUsers.push_back(username);
            }
        }
    }
    
    return timeoutUsers;
}

std::chrono::system_clock::time_point UserManager::getLastHeartbeat(const std::string& username) {
    auto it = users.find(username);
    if (it != users.end()) {
        return it->second.lastHeartbeat;
    }
    return std::chrono::system_clock::now();  // 如果用户不存在，返回当前时间
}

bool UserManager::isUserOnline(const std::string& username) {
    auto it = users.find(username);
    if (it != users.end()) {
        return it->second.isOnline;
    }
    return false;
}
  