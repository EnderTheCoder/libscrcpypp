//
// Created by ender on 25-2-5.
//

#ifndef SCRCPY_CLIENT_HPP
#define SCRCPY_CLIENT_HPP


#include <deque>
#include <filesystem>
#include <ranges>
#include <control_msg.hpp>

#include <boost/asio.hpp>
#include <boost/process/v2/process.hpp>

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

        auto is_connected() const -> bool;

        auto start_recv() -> void;

        auto stop_recv() -> void;

        auto is_recv_enabled() -> bool;

        auto set_frame_consumer(const std::function<void(std::shared_ptr<frame>)> &consumer) -> void;

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

        auto touch(std::int32_t x, std::int32_t y, android_motionevent_action,
                   std::uint64_t pointer_id = pointer_id::GENERIC_FINGER) const -> void;

        auto down_pointer(std::int32_t x, std::int32_t y,
                          std::uint64_t pointer_id = pointer_id::GENERIC_FINGER) const -> void;

        auto up_pointer(std::int32_t x, std::int32_t y,
                        std::uint64_t pointer_id = pointer_id::GENERIC_FINGER) const -> void;

        auto move_pointer(std::int32_t x, std::int32_t y,
                          std::uint64_t pointer_id = pointer_id::GENERIC_FINGER) const -> void;

        auto hover_pointer(std::int32_t x, std::int32_t y, std::uint64_t pointer_id = pointer_id::MOUSE) const -> void;

        auto slide(std::tuple<std::int32_t, std::int32_t> begin, std::tuple<std::int32_t, std::int32_t> end,
                   std::uint64_t pointer_id = pointer_id::GENERIC_FINGER,
                   std::chrono::milliseconds duration = std::chrono::milliseconds(200)) const -> void;

        auto click(std::int32_t x, std::int32_t y, std::uint64_t pointer_id = pointer_id::GENERIC_FINGER) const -> void;

        auto text(const std::string &text) const -> void;

        auto scroll(std::int32_t x, std::int32_t y, float h_scroll, float v_scroll) const -> void;

        auto expand_notification_panel() const -> void;

        auto expand_settings_panel() const -> void;

        auto collapse_panels() const -> void;

        auto rotate_device() const -> void;

        auto open_head_keyboard_settings() const -> void;

        auto reset_video() const -> void;

        auto start_app(const std::string &app_name) const -> void;

        auto back_or_screen_on() const -> void;

        auto inject_keycode(android_keycode keycode, std::uint32_t repeat = 1,
                            android_metastate metastate = android_metastate::AMETA_NONE) const -> void;

    private:
        auto send_single_byte_control_msg(control_msg_type msg_type) const -> void;

        std::string addr;
        std::uint16_t port_;

        std::string device_name{};
        std::string codec{};
        std::uint32_t height{0};
        std::uint32_t width{0};

        std::thread recv_handle;

        std::optional<boost::process::process> server_proc;
        std::optional<boost::asio::readable_pipe> server_rp;

        std::atomic<bool> recv_enabled{false};
        std::atomic<bool> parse_enabled{false};

        std::shared_ptr<boost::asio::ip::tcp::socket> video_socket;
        std::shared_ptr<boost::asio::ip::tcp::socket> control_socket;

        boost::asio::io_context ctx;

        std::mutex frame_mutex;

        std::deque<std::shared_ptr<frame> > frame_queue;

        h264_decoder decoder;

        AVPacket *config_packet = nullptr;

        std::optional<std::function<void(std::shared_ptr<frame>)> > consumer_;
    };
}
#endif //SCRCPY_CLIENT_HPP
