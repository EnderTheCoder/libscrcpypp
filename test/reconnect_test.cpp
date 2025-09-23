//
// Created by ender on 2025/8/20.
//
#include "client.cpp"

int main(int argc, char *argv[]) {
    std::cout << "list of device serials:" << std::endl;
    for (const auto &s: scrcpy::client::list_dev_serials("adb")) {
        std::cout << s << std::endl;
    }
    const auto cli = scrcpy::client::create_shared("localhost", 1234);


    for (int i = 0; i < 10; i++) {
        try {
            cli->terminate();
            cli->deploy("adb", "scrcpy-server", "3.3.1", 1234);
            std::this_thread::sleep_for(std::chrono::seconds(1));
            cli->connect();
            std::cout << "connected to server" << std::endl;
            // break;
        } catch (std::exception &e) {
            std::cerr << e.what() << std::endl;
        }
    }
    return 0;
}
