#ifndef USER_STRUCT_H
#define USER_STRUCT_H

#include <string>
#include <chrono>

struct UserInfo {
    std::string username;
    std::string password;
    std::string email;
    std::string deviceInfo;
    bool isOnline;
    std::chrono::system_clock::time_point lastHeartbeat;
    bool isDisabled;

    UserInfo() : isOnline(false), isDisabled(false) {}
};

#endif // USER_STRUCT_H