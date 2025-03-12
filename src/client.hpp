//
// Created by ender on 25-2-5.
//

#ifndef SCRCPY_CLIENT_HPP
#define SCRCPY_CLIENT_HPP


#include <utility>
#include <deque>
#include <filesystem>
#include <ranges>
#include <bitset>
#include <control_msg.hpp>

#include <boost/asio.hpp>
#include <boost/process.hpp>

#include "decoder.hpp"
#include "frame.hpp"

namespace scrcpy {
    class client : public std::enable_shared_from_this<client> {
    public:
        static auto create_shared(std::string_view addr, std::uint16_t port) -> std::shared_ptr<client>;

        client(std::string_view addr, std::uint16_t port);

        ~client();

        auto get_port() const -> std::uint16_t;

        auto get_addr() const -> std::string_view;

        auto connect() -> void;

        auto start_recv() -> void;

        auto stop_recv() -> void;

        auto is_recv_enabled() -> bool;

        auto set_frame_consumer(std::function<void(std::shared_ptr<frame>)> consumer) -> void;

        auto frames() -> std::vector<std::shared_ptr<frame> >;

        auto video_size() -> std::tuple<std::uint64_t, std::uint64_t>;

        static auto read_forward(const std::filesystem::path &adb_bin) -> std::vector<std::array<std::string, 3> >;

        static auto forward_list_contains_tcp_port(
            const std::filesystem::path &adb_bin, std::uint16_t port) -> std::optional<std::string>;

        static auto list_dev_serials(const std::filesystem::path &adb_bin) -> std::vector<std::string>;

        auto get_codec() -> std::string {
            return this->codec;
        }

        auto run_recv() -> void;

        auto deploy(const std::filesystem::path &adb_bin,
                    const std::filesystem::path &scrcpy_jar_bin,
                    const std::string &scrcpy_server_version,
                    std::uint16_t port,
                    const std::optional<std::string> &device_serial = std::nullopt,
                    const std::optional<std::uint16_t> &max_size = std::nullopt) -> void;

        auto terminate() -> void;

        auto server_alive() -> bool;

        auto send_control_msg(const std::shared_ptr<control_msg> &msg) const -> void;

        auto get_server_dbg_logs() -> std::vector<std::string>;

        auto touch(std::int32_t x, std::int32_t y, android_keyevent_action,
                   std::uint64_t pointer_id = pointer_id::GENERIC_FINGER) const -> void;

        auto click(std::int32_t x, std::int32_t y, std::uint64_t pointer_id = pointer_id::GENERIC_FINGER) const -> void;

        auto expand_notification_panel() const -> void;

        auto expand_settings_panel() const -> void;

        auto collapse_panels() const -> void;

        auto rotate_device() const -> void;

        auto open_head_keyboard_settings() const -> void;

        auto reset_video() const -> void;

    private:
        auto send_single_byte_control_msg(control_msg_type msg_type) const -> void;

        std::string addr;
        std::uint16_t port;

        std::string device_name{};
        std::string codec{};
        std::uint32_t height{0};
        std::uint32_t width{0};

        std::thread recv_handle;

        boost::process::child server_c;
        boost::process::ipstream server_out_stream;

        std::atomic<bool> recv_enabled{false};
        std::atomic<bool> parse_enabled{false};

        std::shared_ptr<boost::asio::ip::tcp::socket> video_socket;
        std::shared_ptr<boost::asio::ip::tcp::socket> control_socket;

        std::shared_ptr<boost::asio::io_context> io_context;

        std::mutex frame_mutex;

        std::deque<std::shared_ptr<frame> > frame_queue;

        h264_decoder decoder;

        AVPacket *config_packet = nullptr;

        std::optional<std::function<void(std::shared_ptr<frame>)> > consumer;
    };
}
#endif //SCRCPY_CLIENT_HPP
