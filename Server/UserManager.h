#ifndef USER_MANAGER_H
#define USER_MANAGER_H

#include <string>
#include <unordered_map>
#include "../Common/UserStruct.h"

class UserManager {
public:
    UserManager();
    ~UserManager();

    bool registerUser(const UserInfo& userInfo);
    bool loginUser(const std::string& username, const std::string& password);
    bool changePassword(const std::string& username, const std::string& oldPassword, const std::string& newPassword);
    void updateUserStatus(const std::string& username, bool isOnline);

private:
    std::unordered_map<std::string, UserInfo> users;
    bool verifyPassword(const std::string& inputPassword, const std::string& storedPassword);
    std::string encryptPassword(const std::string& password);

    void loadUsersFromFile();
    void saveUsersToFile();
};

#endif // USER_MANAGER_H 