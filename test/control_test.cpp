//  ______   ___   __    ______   ______   ______   _________  ___   ___   ______   ______   ______   ______   ______   ______
// /_____/\ /__/\ /__/\ /_____/\ /_____/\ /_____/\ /________/\/__/\ /__/\ /_____/\ /_____/\ /_____/\ /_____/\ /_____/\ /_____/\
// \::::_\/_\::\_\\  \ \\:::_ \ \\::::_\/_\:::_ \ \\__.::.__\/\::\ \\  \ \\::::_\/_\:::__\/ \:::_ \ \\:::_ \ \\::::_\/_\:::_ \ \
//  \:\/___/\\:. `-\  \ \\:\ \ \ \\:\/___/\\:(_) ) )_ \::\ \   \::\/_\ .\ \\:\/___/\\:\ \  __\:\ \ \ \\:\ \ \ \\:\/___/\\:(_) ) )_
//   \::___\/_\:. _    \ \\:\ \ \ \\::___\/_\: __ `\ \ \::\ \   \:: ___::\ \\::___\/_\:\ \/_/\\:\ \ \ \\:\ \ \ \\::___\/_\: __ `\ \
//    \:\____/\\. \`-\  \ \\:\/.:| |\:\____/\\ \ `\ \ \ \::\ \   \: \ \\::\ \\:\____/\\:\_\ \ \\:\_\ \ \\:\/.:| |\:\____/\\ \ `\ \ \
//     \_____\/ \__\/ \__\/ \____/_/ \_____\/ \_\/ \_\/  \__\/    \__\/ \::\/ \_____\/ \_____\/ \_____\/ \____/_/ \_____\/ \_\/ \_\/
//
// Copyright (C) 2025 EnderTheCoder ggameinvader@gmail.com
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

//
// Created by ender on 25-3-12.
//
#include <client.hpp>
#include <boost/program_options.hpp>
#include <iostream>
#include <optional>

using namespace scrcpy;
namespace po = boost::program_options;

auto main(int argc, char* argv[]) -> int {
    try {
        po::options_description desc("Scrcpy++ Control Test Options");
        desc.add_options()
                    ("help,h", "Show help information")
                    ("addr,a", po::value<std::string>()->default_value("localhost"), "Server address")
                    ("port,p", po::value<int>()->default_value(1234), "Server port")
                    ("adb-path", po::value<std::string>()->default_value("adb"), "ADB executable path")
                    ("scrcpy-server-path", po::value<std::string>()->default_value("scrcpy-server"), "Scrcpy server jar file path")
                    ("server-version", po::value<std::string>(), "Scrcpy server version")
                    ("device-serial,s", po::value<std::string>(), "Device serial number (optional)")
                    ("max-size,m", po::value<int>()->default_value(1920), "Maximum screen size")
                    ("app-package", po::value<std::string>()->default_value("com.baidu.BaiduMap"), "Application package name to launch");

        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);

        if (vm.count("help")) {
            std::cout << desc << std::endl;
            return 0;
        }

        std::string addr = vm["addr"].as<std::string>();
        int port = vm["port"].as<int>();
        std::string adb_path = vm["adb-path"].as<std::string>();
        std::string scrcpy_server_path = vm["scrcpy-server-path"].as<std::string>();
        std::string server_version = vm["server-version"].as<std::string>();
        std::optional<std::string> device_serial = vm.count("device-serial")
            ? std::make_optional(vm["device-serial"].as<std::string>())
            : std::nullopt;
        int max_size = vm["max-size"].as<int>();
        std::string app_package = vm["app-package"].as<std::string>();

        const auto cli = client::create_shared(addr, port);
        cli->deploy(
            adb_path,
            scrcpy_server_path,
            server_version,
            port,
            device_serial,
            max_size
        );

        std::this_thread::sleep_for(std::chrono::seconds(1));
        cli->connect();
        cli->start_app(app_package);
        cli->click(100, 200);
        cli->text("hello, world!");
        cli->slide(std::make_tuple(100, 100), std::make_tuple(800, 800));
        cli->slide(std::make_tuple(100, 800), std::make_tuple(800, 100));
        cli->scroll(260, 1260, 1.0, -1.0);
        std::this_thread::sleep_for(std::chrono::seconds(1));

        cli->back_or_screen_on();
        cli->inject_keycode(android_keycode::AKEYCODE_BRIGHTNESS_DOWN);
        cli->inject_keycode(android_keycode::AKEYCODE_BRIGHTNESS_DOWN);
        cli->inject_keycode(android_keycode::AKEYCODE_BRIGHTNESS_DOWN);

        std::this_thread::sleep_for(std::chrono::seconds(1));
        return 0;

    } catch (const std::exception& e) {
        std::cerr << "err: " << e.what() << std::endl;
        return 1;
    }
}
