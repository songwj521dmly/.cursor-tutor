#include "Protocol.h"
#include <sstream>

std::string Protocol::createResponse(ResponseStatus status, const std::string& message) {
    return std::to_string(static_cast<int>(status)) + "|" + message;
}

bool Protocol::parseUserInfo(const std::string& message, UserInfo& userInfo) {
    std::istringstream stream(message);
    std::string token;
    
    if (!std::getline(stream, userInfo.username, '|')) return false;
    if (!std::getline(stream, userInfo.password, '|')) return false;
    if (!std::getline(stream, userInfo.email, '|')) return false;
    if (!std::getline(stream, userInfo.deviceInfo)) return false;

    return true;
}

std::string Protocol::serializeUserInfo(const UserInfo& user) {
    std::stringstream ss;
    ss << user.username << "|"
       << user.password << "|"
       << user.email << "|"
       << user.deviceInfo;
    return ss.str();
} 