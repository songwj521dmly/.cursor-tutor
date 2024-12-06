#include "Server.h"
#include <iostream>
#include <windows.h>
#include <fcntl.h>
#include <io.h>

int main() {
    // 设置控制台代码页
    SetConsoleOutputCP(936);    // 设置输出代码页为简体中文
    SetConsoleCP(936);          // 设置输入代码页为简体中文
    
    // 设置标准输出为二进制模式
    _setmode(_fileno(stdout), _O_BINARY);
    
    try {
        Server server;
        std::cout << "启动服务器..." << std::endl;
        server.start();
    }
    catch (const std::exception& e) {
        std::cerr << "服务器错误: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
} 