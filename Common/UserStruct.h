#ifndef USER_STRUCT_H
#define USER_STRUCT_H

#include <string>
#include <chrono>

struct UserInfo {
    std::string username;
    std::string password;
    std::string email;
    std::string deviceInfo;
    std::chrono::system_clock::time_point lastHeartbeat;  // 用于跟踪用户的最后活动时间
    bool isDisabled = false;  // 用户状态标志，默认为 false
};

#endif // USER_STRUCT_H