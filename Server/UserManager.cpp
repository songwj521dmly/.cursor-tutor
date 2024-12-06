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
        UserInfo& user = it->second;
        if (isOnline) {
            user.lastHeartbeat = std::chrono::system_clock::now();
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