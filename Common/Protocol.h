#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <string>
#include "UserStruct.h"

enum class ResponseStatus {
    SUCCESS = 0,
    FAILED = 1,
    USER_EXISTS = 2,
    FORCE_LOGOUT = 3
};

class Protocol {
public:
    // 创建响应消息
    static std::string createResponse(ResponseStatus status, const std::string& message);

    // 解析用户信息
    static bool parseUserInfo(const std::string& message, UserInfo& userInfo);

    // 序列化用户信息
    static std::string serializeUserInfo(const UserInfo& user);
};

#endif // PROTOCOL_H 