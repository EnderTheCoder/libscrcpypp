//
// Created by ender on 25-2-5.
//

#ifndef SCRCPY_CLIENT_HPP
#define SCRCPY_CLIENT_HPP


#include <iostream>
#include <utility>
#include <queue>
#include <filesystem>
#include <ranges>
#include <boost/asio.hpp>
#include <boost/process.hpp>

namespace scrcpy {
    class client : public std::enable_shared_from_this<client> {
    public:
        client(std::string addr, const std::uint16_t port) : addr(std::move(addr)), port(port) {
        }

        ~client() {
            server_c.terminate();
        }

        auto connect() {
            using boost::asio::ip::tcp;
            boost::asio::io_context io_context;

            tcp::resolver resolver(io_context);
            const auto endpoints = resolver.resolve(addr, std::to_string(port));

            this->video_socket = std::make_shared<tcp::socket>(io_context);
            boost::asio::connect(*this->video_socket, endpoints);

            std::array<char, 1> dummy_byte_buffer = {};
            try {
                this->video_socket->read_some(boost::asio::buffer(dummy_byte_buffer));
                if (dummy_byte_buffer[0] != 0x00) {
                    throw std::runtime_error(std::format("broken packet, expect 0x00 but got {:#x}.",
                                                         dummy_byte_buffer[0]));
                }
                std::cout << "successfully read dummy byte." << std::endl;
            } catch (std::exception &e) {
                std::cerr << "error reading dummy byte: " << e.what() << std::endl;
                return;
            }
            std::array<char, 64> device_name_buffer = {};
            this->video_socket->read_some(boost::asio::buffer(device_name_buffer));
            this->device_name = device_name_buffer.data();
            std::cout << "device name: " << device_name << std::endl;
            std::array<std::byte, 12> codec_meta_buffer = {};
            this->video_socket->read_some(boost::asio::buffer(codec_meta_buffer));
            this->codec = std::string{reinterpret_cast<char *>(codec_meta_buffer.data()), 4};
            std::reverse(codec_meta_buffer.begin() + 4, codec_meta_buffer.begin() + 8);
            std::reverse(codec_meta_buffer.begin() + 8, codec_meta_buffer.end());
            this->width = *reinterpret_cast<std::uint32_t *>(codec_meta_buffer.data() + 4);
            this->height = *reinterpret_cast<std::uint32_t *>(codec_meta_buffer.data() + 8);
            std::cout << "video stream working at resolution " << this->height << "x" << this->width << std::endl;
        }

        auto start_recv() {
            this->recv_enabled = true;
            std::thread t([this] {
                while (true) {
                    if (not recv_enabled) {
                        break;
                    }
                    std::vector<std::byte> frame_buffer;
                    frame_buffer.reserve(0x10000);

                    while (true) {
                        std::array<std::byte, 0x10000> net_buffer = {};

                        const auto size = this->video_socket->read_some(boost::asio::buffer(net_buffer));
                        frame_buffer.insert(frame_buffer.end(), net_buffer.begin(), net_buffer.begin() + size);
                        if (size < 0x10000) {
                            break;
                        }
                    }
                    std::cout << "frame received with size" << frame_buffer.size() << std::endl;
                    std::lock_guard guard(frame_mutex);
                    this->frame_queue.emplace(std::move(frame_buffer));
                    if (this->frame_queue.size() > 3) {
                        this->frame_queue.pop();
                    }
                }
            });
            t.detach();
        }

        auto stop_recv() {
            this->recv_enabled = false;
        }

        auto frame() {
            std::lock_guard guard(frame_mutex);
            return this->frame_queue.front();
        }

        std::tuple<std::uint64_t, std::uint64_t> get_w_size() {
            return {width, height};
        }

        static auto read_forward(const std::filesystem::path &adb_bin) {
            using namespace boost::process;
            ipstream out_stream;
            using std::operator""sv;
            child list_c(std::format("{} forward --list", adb_bin.string()), std_out > out_stream);
            std::vector<std::array<std::string, 3> > forward_list;
            list_c.wait();
            for (std::string line; out_stream && std::getline(out_stream, line) && !line.empty();) {
                std::cout << "line: " << line << std::endl;
                auto item = std::array<std::string, 3>{};
                for (const auto [idx, part]: std::views::split(line, " "sv) | std::views::enumerate) {
                    item.at(idx) = std::string_view(part);
                }
                forward_list.emplace_back(item);
            }
            return forward_list;
        }

        static std::optional<std::string> forward_list_contains_tcp_port(
            const std::filesystem::path &adb_bin, const std::uint16_t port) {
            for (const auto &[serial, local, remote]: read_forward(adb_bin)) {
                if (local.contains(std::format("tcp:{}", port))) {
                    return serial;
                }
            }
            return std::nullopt;
        }

        static auto list_dev_serials(const std::filesystem::path &adb_bin) {
            using namespace boost::process;
            ipstream out_stream;
            using std::operator""sv;
            child list_c(std::format("{} devices", adb_bin.string()), std_out > out_stream);
            auto sig_start = false;
            std::vector<std::string> serials;
            list_c.wait();
            for (std::string line; out_stream && std::getline(out_stream, line) && !line.empty();) {
                if (sig_start) {
                    for (const auto [s_begin, s_end]: std::views::split(line, "\t"sv)) {
                        auto serial = std::string_view(s_begin, s_end);
                        serials.emplace_back(serial);
                        break;
                    }
                } else if (line == "List of devices attached") {
                    sig_start = true;
                }
            }
            return serials;
        }

        auto get_codec() {
            return this->codec;
        }

        auto deploy(const std::filesystem::path &adb_bin,
                    const std::filesystem::path &scrcpy_jar_bin,
                    const std::string &scrcpy_server_version,
                    const std::uint16_t port,
                    const std::optional<std::string> &device_serial = std::nullopt) {
            //adb shell CLASSPATH=/sdcard/scrcpy-server.jar app_process / com.genymobile.scrcpy.Server 3.1 tunnel_forward=true cleanup=false audio=false control=false max_size=1920
            using namespace boost::process;
            ipstream out_stream;
            auto adb_exec = adb_bin.string();
            std::string serial;
            if (device_serial.has_value()) {
                adb_exec += " -s " + device_serial.value();
                serial = device_serial.value();
            } else {
                auto serial_c = child(std::format("{} get-serialno", adb_exec), std_out > out_stream);
                serial_c.wait();
                if (serial_c.exit_code() != 0) {
                    throw std::runtime_error("failed to get adb device serialno");
                }
                for (std::string line; out_stream && std::getline(out_stream, line) && !line.empty();) {
                    serial = line;
                    break; // read first line only
                }
            }
            auto upload_cmd = std::format("{} push {} /sdcard/scrcpy-server.jar", adb_exec, scrcpy_jar_bin.string());
            auto forward_cmd = std::format("{} forward tcp:{} localabstract:scrcpy", adb_exec, port);
            auto exec_cmd = std::format(
                "{} shell CLASSPATH=/sdcard/scrcpy-server.jar app_process / com.genymobile.scrcpy.Server"
                " {} tunnel_forward=true cleanup=true audio=false control=false",
                adb_exec, scrcpy_server_version
            );

            child upload_c(upload_cmd);
            upload_c.wait();
            if (upload_c.exit_code() != 0) {
                throw std::runtime_error("error uploading scrcpy server jar");
            }

            if (const auto existing_serial = forward_list_contains_tcp_port(adb_bin, port);
                existing_serial.has_value()) {
                if (existing_serial.value() != serial) {
                    throw std::runtime_error(
                        std::format(
                            "another adb device[serial={}] is forwarding on this port[{}]",
                            existing_serial.value(), port)
                    );
                }
            } else {
                child forward_c(forward_cmd, std_out > out_stream);
                forward_c.wait();
                if (forward_c.exit_code() != 0) {
                    throw std::runtime_error("error forwarding scrcpy to local tcp port");
                }
            }

            server_c = child{exec_cmd};
        }

    private:
        std::string addr;
        std::uint16_t port;

        std::string device_name{};
        std::string codec{};
        std::uint32_t height{0};
        std::uint32_t width{0};

        boost::process::child server_c;

        std::atomic<bool> recv_enabled{false};

        std::shared_ptr<boost::asio::ip::tcp::socket> video_socket;

        std::mutex frame_mutex;
        std::queue<std::vector<std::byte> > frame_queue;
    };
}
#endif //SCRCPY_CLIENT_HPP
