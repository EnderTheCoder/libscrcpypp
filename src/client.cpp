//
// Created by ender on 25-2-15.
//
#include <client.hpp>

namespace scrcpy {
    auto client::create_shared(std::string_view addr, std::uint16_t port) -> std::shared_ptr<client> {
        return std::make_shared<client>(addr, port);
    }

    client::client(const std::string_view addr, const std::uint16_t port) : addr(addr), port(port) {
    }

    client::~client() {
        stop_recv();
        if (recv_handle.joinable()) recv_handle.join();
        if (config_packet != nullptr) {
            av_packet_free(&config_packet);
        }
        if (video_socket != nullptr and video_socket->is_open()) {
            video_socket->cancel();
            video_socket->close();
        }
        if (control_socket != nullptr and control_socket->is_open()) {
            control_socket->cancel();
            control_socket->close();
        }

        if (server_c.running()) {
            server_c.terminate();
            server_c.wait();
        }
    }

    auto client::get_port() const -> std::uint16_t { return port; }

    auto client::get_addr() const -> std::string_view { return addr; }

    auto client::connect() -> void {
        using boost::asio::ip::tcp;
        io_context = std::make_shared<boost::asio::io_context>();

        tcp::resolver resolver(*io_context);
        const auto endpoints = resolver.resolve(addr, std::to_string(port));

        if (this->video_socket != nullptr and video_socket->is_open()) {
            video_socket->close();
        }
        this->video_socket = std::make_shared<tcp::socket>(*io_context);
        boost::asio::connect(*this->video_socket, endpoints);

        if (this->control_socket != nullptr and control_socket->is_open()) {
            control_socket->close();
        }
        this->control_socket = std::make_shared<tcp::socket>(*io_context);
        boost::asio::connect(*this->control_socket, endpoints);

        std::array<char, 1> dummy_byte_buffer = {};
        try {
            boost::asio::read(*video_socket, boost::asio::buffer(dummy_byte_buffer));
            if (dummy_byte_buffer[0] != 0x00) {
                throw std::runtime_error(std::format("broken packet, expect 0x00 but got {:#x}.",
                                                     dummy_byte_buffer[0]));
            }
            std::cout << "successfully read dummy byte." << std::endl;
        } catch (std::exception &e) {
            throw std::runtime_error(std::format("error reading dummy byte: {}", e.what()));
        }
        std::array<char, 64> device_name_buffer = {};
        boost::asio::read(*video_socket, boost::asio::buffer(device_name_buffer));
        this->device_name = device_name_buffer.data();
        std::cout << "device name: " << device_name << std::endl;
        std::array<std::byte, 12> codec_meta_buffer = {};
        boost::asio::read(*video_socket, boost::asio::buffer(codec_meta_buffer));
        this->codec = std::string{reinterpret_cast<char *>(codec_meta_buffer.data()), 4};
        std::reverse(codec_meta_buffer.begin() + 4, codec_meta_buffer.begin() + 8);
        std::reverse(codec_meta_buffer.begin() + 8, codec_meta_buffer.end());
        this->width = *reinterpret_cast<std::uint32_t *>(codec_meta_buffer.data() + 4);
        this->height = *reinterpret_cast<std::uint32_t *>(codec_meta_buffer.data() + 8);\
        std::cout << "video stream codec: " << this->codec << std::endl;
        std::cout << "video stream working at resolution: " << this->height << "x" << this->width << std::endl;
    }

    auto client::is_connected() const -> bool {
        return this->video_socket != nullptr and video_socket->is_open() and control_socket != nullptr and control_socket->is_open();
    }

    auto client::run_recv() -> void {
        try {
            recv_enabled = true;
            while (true) {
                if (not recv_enabled) {
                    break;
                }
                std::array<std::uint8_t, 12> frame_header_buffer{};

                boost::asio::read(*video_socket, boost::asio::buffer(frame_header_buffer));
                const bool config_flag = frame_header_buffer.at(0) >> 7 & 0x01;
                const bool keyframe_flag = frame_header_buffer.at(0) >> 6 & 0x01;
                std::reverse(frame_header_buffer.begin(), frame_header_buffer.begin() + 8);
                frame_header_buffer.at(7) <<= 2;
                const auto pts = *reinterpret_cast<std::uint64_t *>(frame_header_buffer.data());
                std::reverse(frame_header_buffer.begin() + 8, frame_header_buffer.end());
                const auto packet_size = *reinterpret_cast<std::uint32_t *>(frame_header_buffer.data() + 8);


                AVPacket *packet = av_packet_alloc();
                if (av_new_packet(packet, static_cast<std::int32_t>(packet_size))) {
                    throw std::runtime_error("failed to allocate packet memory: ");
                }
                const auto frame_size = boost::asio::read(*this->video_socket,
                                                          boost::asio::buffer(packet->data, packet_size));
                packet->size = static_cast<std::int32_t>(packet_size);

                if (frame_size != packet_size) {
                    av_packet_free(&packet);
                    if (this->config_packet != nullptr) {
                        av_packet_free(&this->config_packet);
                    }
                    std::cerr << "end of video stream" << std::endl;
                    this->recv_enabled = false;
                    this->video_socket->close();
                    if (this->consumer.has_value()) {
                        this->consumer.value()(nullptr);
                    }
                    return;
                }

                if (config_flag) {
                    packet->pts = AV_NOPTS_VALUE;
                } else {
                    packet->pts = static_cast<std::int64_t>(pts);
                }

                if (keyframe_flag) {
                    packet->flags |= AV_PKT_FLAG_KEY;
                }

                packet->dts = packet->pts;
                if (config_flag) {
                    config_packet = packet;
                } else if (config_packet != nullptr) {
                    if (av_grow_packet(packet, config_packet->size)) {
                        throw std::runtime_error("failed to grow packet");
                    }
                    memmove(packet->data + config_packet->size, packet->data, packet->size);
                    memcpy(packet->data, config_packet->data, config_packet->size);
                    // packet->size += config_packet->size;
                    av_packet_free(&config_packet);
                    config_packet = nullptr;
                }
                const auto frames = decoder.decode(packet);
                if (frames.empty()) {
                    continue;
                }

                if (this->consumer.has_value()) {
                    for (const auto &frame: frames) {
                        this->consumer.value()(frame);
                    }
                    continue;
                }

                frame_mutex.lock();
                frame_queue.insert(frame_queue.end(), frames.begin(), frames.end());
                frame_mutex.unlock();
            }
        } catch (std::exception &) {
            this->recv_enabled = false;
            throw;
        }
    }

    auto client::start_recv() -> void {
        if (this->recv_handle.joinable()) {
            std::cerr << "waiting for previous network thread to exit.." << std::endl;
            this->recv_handle.join();
            std::cerr << "network thread exited." << std::endl;
        }
        recv_handle = std::thread([t = shared_from_this()] {
            try {
                t->run_recv();
            } catch (std::exception &e) {
                std::cerr << "recv stopped: " << e.what() << std::endl;
            }
        });
    }

    auto client::stop_recv() -> void {
        this->recv_enabled = false;
        if (this->recv_handle.joinable()) {
            this->recv_handle.join();
        }
    }

    auto client::is_recv_enabled() -> bool {
        return this->recv_enabled;
    }

    auto client::set_frame_consumer(const std::function<void(std::shared_ptr<frame>)> &consumer) -> void {
        this->consumer = consumer;
    }

    auto client::frames() -> std::vector<std::shared_ptr<frame> > {
        frame_mutex.lock();
        if (frame_queue.empty()) {
            return {};
        }
        std::vector<std::shared_ptr<frame> > frames = {};
        frames.insert(frames.end(), frame_queue.begin(), frame_queue.end());
        frame_queue.clear();
        frame_mutex.unlock();
        return frames;
    }

    auto client::video_size() -> std::tuple<std::uint64_t, std::uint64_t> {
        return {width, height};
    }

    auto client::read_forward(
        const std::filesystem::path &adb_bin) -> std::vector<std::array<std::string, 3> > {
        using namespace boost::process;
        ipstream out_stream;
        using std::operator ""sv;
        child list_c(std::format("{} forward --list", adb_bin.string()), std_out > out_stream);
        std::vector<std::array<std::string, 3> > forward_list;
        list_c.wait();
        for (std::string line; out_stream && std::getline(out_stream, line) && !line.empty();) {
            auto item = std::array<std::string, 3>{};
            for (const auto [idx, part]: std::views::split(line, " "sv) | std::views::enumerate) {
                item.at(idx) = std::string_view(part);
            }
            forward_list.emplace_back(item);
        }
        return forward_list;
    }

    std::optional<std::string> client::forward_list_contains_tcp_port(
        const std::filesystem::path &adb_bin,
        const std::uint16_t port) {
        for (const auto &[serial, local, remote]: read_forward(adb_bin)) {
            if (local.contains(std::format("tcp:{}", port))) {
                return serial;
            }
        }
        return std::nullopt;
    }

    auto client::list_dev_serials(const std::filesystem::path &adb_bin) -> std::vector<std::string> {
        using namespace boost::process;
        ipstream out_stream;
        using std::operator ""sv;
        child list_c(std::format("{} devices", adb_bin.string()), std_out > out_stream);
        auto sig_start = false;
        std::vector<std::string> serials;
        list_c.wait();
        for (std::string line; out_stream && std::getline(out_stream, line) && !line.empty();) {
            if (sig_start and line.contains("device")) {
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

    auto client::deploy(const std::filesystem::path &adb_bin,
                        const std::filesystem::path &scrcpy_jar_bin,
                        const std::string &scrcpy_server_version, const std::uint16_t port,
                        const std::optional<std::string> &device_serial,
                        const std::optional<std::uint16_t> &max_size) -> void {
        //adb shell CLASSPATH=/sdcard/scrcpy-server.jar app_process / com.genymobile.scrcpy.Server 3.1 tunnel_forward=true cleanup=false audio=false control=false max_size=1920
        using namespace boost::process;
        auto adb_exec = adb_bin.string();
        std::string serial;
        if (device_serial.has_value()) {
            adb_exec += " -s " + device_serial.value();
            serial = device_serial.value();
        } else {
            ipstream out_stream;
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

        if (server_c.running()) {
            std::cerr << std::format("[{}]scrcpy server it already running, terminating...", serial) << std::endl;
            server_c.terminate();
            std::cerr << std::format("[{}]scrcpy server terminated", serial) << std::endl;
        }

        auto param_max_size = max_size.has_value() ? std::format("max_size={}", max_size.value()) : "";

        auto upload_cmd = std::format("{} push {} /sdcard/scrcpy-server.jar", adb_exec, scrcpy_jar_bin.string());
        auto forward_cmd = std::format("{} forward tcp:{} localabstract:scrcpy", adb_exec, port);
        auto exec_cmd = std::format(
            "{} shell CLASSPATH=/sdcard/scrcpy-server.jar app_process / com.genymobile.scrcpy.Server"
            " {} tunnel_forward=true cleanup=true video=true audio=false control=true {}",
            adb_exec, scrcpy_server_version, param_max_size
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
            ipstream out_stream;
            child forward_c(forward_cmd, std_out > out_stream);
            forward_c.wait();
            if (forward_c.exit_code() != 0) {
                std::string cause;
                for (std::string line; out_stream && std::getline(out_stream, line) && !line.empty();) {
                    cause += line;
                }
                throw std::runtime_error(std::format("error forwarding scrcpy to local tcp port: {}", cause));
            }
        }
        server_out_stream = ipstream();
        server_c = child{exec_cmd, std_out > server_out_stream};

        std::string first_line;
        bool output_received = false;
        auto start_time = std::chrono::steady_clock::now();
        while (true) {
            constexpr int timeout_ms = 10000;
            if (auto elapsed = std::chrono::steady_clock::now() - start_time;
                std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() > timeout_ms) {
                server_c.terminate();
                throw std::runtime_error("server startup timed out (10s)");
            }

            if (!server_c.running()) {
                int exit_code = server_c.exit_code();
                throw std::runtime_error(std::format("server process exited unexpectedly (code: {})", exit_code));
            }

            if (std::getline(server_out_stream, first_line)) {
                if (not first_line.empty() and first_line.contains("[server]")) {
                    output_received = true;
                    break;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }

        if (!output_received) {
            server_c.terminate();
            throw std::runtime_error("failed to get server startup confirmation");
        }
    }

    auto client::terminate() -> void {
        if (this->server_c.running()) {
            this->server_c.terminate();
        }
    }

    auto client::server_alive() -> bool {
        return this->server_c.running();
    }

    auto client::send_control_msg(const std::shared_ptr<control_msg> &msg) const -> void {
        auto buffer = msg->serialize();
        this->control_socket->send(boost::asio::buffer(buffer, buffer.size()));
    }

    auto client::get_server_dbg_logs() -> std::vector<std::string> {
        std::vector<std::string> dbg_logs;
        for (std::string line; this->server_out_stream && std::getline(this->server_out_stream, line) && !line.empty()
             ;) {
            dbg_logs.push_back(line);
        }
        return dbg_logs;
    }

    auto client::touch(const std::int32_t x, const std::int32_t y, const android_motionevent_action action,
                       const std::uint64_t pointer_id) const -> void {
        auto msg = std::make_unique<touch_msg>();
        msg->action = abs_enum_t{action};
        msg->pointer_id = abs_int_t{pointer_id};
        auto position = position_t(x, y, this->width, this->height);
        msg->position = position;
        msg->pressure = ufp16_t{1};
        msg->action_button = abs_enum_t<android_motionevent_buttons, std::uint32_t>{
            android_motionevent_buttons::AMOTION_EVENT_BUTTON_PRIMARY
        };
        msg->buttons = abs_enum_t<android_motionevent_buttons, std::uint32_t>{
            android_motionevent_buttons::AMOTION_EVENT_BUTTON_PRIMARY
        };
        this->send_control_msg(std::move(msg));
    }

    auto client::down_pointer(const std::int32_t x, const std::int32_t y,
                              const std::uint64_t pointer_id) const -> void {
        this->touch(x, y, android_motionevent_action::AMOTION_EVENT_ACTION_DOWN, pointer_id);
    }

    auto client::up_pointer(const std::int32_t x, const std::int32_t y, const std::uint64_t pointer_id) const -> void {
        this->touch(x, y, android_motionevent_action::AMOTION_EVENT_ACTION_UP, pointer_id);
    }

    void client::move_pointer(const std::int32_t x, const std::int32_t y, const std::uint64_t pointer_id) const {
        this->touch(x, y, android_motionevent_action::AMOTION_EVENT_ACTION_MOVE, pointer_id);
    }

    auto client::hover_pointer(const std::int32_t x, const std::int32_t y,
                               const std::uint64_t pointer_id) const -> void {
        this->touch(x, y, android_motionevent_action::AMOTION_EVENT_ACTION_HOVER_MOVE, pointer_id);
    }

    auto client::slide(std::tuple<std::int32_t, std::int32_t> begin, std::tuple<std::int32_t, std::int32_t> end,
                       const std::uint64_t pointer_id, std::chrono::milliseconds duration) const -> void {
        auto &[x0, y0] = begin;
        auto &[x1, y1] = end;

        auto x_diff = x1 - x0;
        auto y_diff = y1 - y0;
        auto abs_step = std::min(std::abs(x_diff), abs(y_diff));
        auto x_step = x_diff / abs_step;
        auto y_step = y_diff / abs_step;

        this->down_pointer(x0, y0, pointer_id);
        for (auto i = 0; i < abs_step; i++) {
            this->move_pointer(x0 + i * x_step, y0 + i * y_step, pointer_id);
            std::this_thread::sleep_for(duration / abs_step);
        }
        this->up_pointer(x1, y1, pointer_id);
    }

    auto client::click(const std::int32_t x, const std::int32_t y, const std::uint64_t pointer_id) const -> void {
        this->touch(x, y, android_motionevent_action::AMOTION_EVENT_ACTION_DOWN, pointer_id);
        this->touch(x, y, android_motionevent_action::AMOTION_EVENT_ACTION_UP, pointer_id);
    }

    auto client::text(const std::string &text) const -> void {
        auto msg = std::make_unique<text_msg>();
        msg->text = string_t{text, 300};
        this->send_control_msg(std::move(msg));
    }

    auto client::expand_notification_panel() const -> void {
        this->send_single_byte_control_msg(control_msg_type::SC_CONTROL_MSG_TYPE_EXPAND_NOTIFICATION_PANEL);
    }

    auto client::expand_settings_panel() const -> void {
        this->send_single_byte_control_msg(control_msg_type::SC_CONTROL_MSG_TYPE_EXPAND_SETTINGS_PANEL);
    }

    auto client::collapse_panels() const -> void {
        this->send_single_byte_control_msg(control_msg_type::SC_CONTROL_MSG_TYPE_COLLAPSE_PANELS);
    }

    auto client::rotate_device() const -> void {
        this->send_single_byte_control_msg(control_msg_type::SC_CONTROL_MSG_TYPE_ROTATE_DEVICE);
    }

    auto client::open_head_keyboard_settings() const -> void {
        this->send_single_byte_control_msg(control_msg_type::SC_CONTROL_MSG_TYPE_OPEN_HARD_KEYBOARD_SETTINGS);
    }

    auto client::reset_video() const -> void {
        this->send_single_byte_control_msg(control_msg_type::SC_CONTROL_MSG_TYPE_RESET_VIDEO);
    }

    auto client::start_app(const std::string &app_name) const -> void {
        auto msg = std::make_unique<start_app_msg>();
        msg->app_name = string_t<abs_int_t<std::uint8_t> >{app_name};
        this->send_control_msg(std::move(msg));
    }


    auto client::back_or_screen_on() const -> void {
        auto msg = std::make_unique<back_or_screen_on_msg>();
        msg->action = abs_enum_t{
            android_keyevent_action::AKEY_EVENT_ACTION_DOWN
        };
        this->send_control_msg(std::move(msg));
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
        msg = std::make_unique<back_or_screen_on_msg>();
        msg->action = abs_enum_t{
            android_keyevent_action::AKEY_EVENT_ACTION_UP
        };
        this->send_control_msg(std::move(msg));
    }

    auto client::inject_keycode(const android_keycode keycode, const std::uint32_t repeat, const android_metastate metastate) const -> void {
        auto msg = std::make_unique<inject_keycode_msg>();
        msg->action = abs_enum_t{
            android_keyevent_action::AKEY_EVENT_ACTION_DOWN
        };
        msg->keycode = abs_enum_t<android_keycode, std::uint32_t>{keycode};
        msg->repeat = abs_int_t{repeat};
        msg->metastate = abs_enum_t<android_metastate, std::uint32_t>{metastate};
        this->send_control_msg(std::move(msg));

        std::this_thread::sleep_for(std::chrono::milliseconds{10});

        msg = std::make_unique<inject_keycode_msg>();
        msg->action = abs_enum_t{
            android_keyevent_action::AKEY_EVENT_ACTION_UP
        };
        msg->keycode = abs_enum_t<android_keycode, std::uint32_t>{keycode};
        msg->repeat = abs_int_t{repeat};
        msg->metastate = abs_enum_t<android_metastate, std::uint32_t>{metastate};
        this->send_control_msg(std::move(msg));
    }

    auto client::scroll(const std::int32_t x, const std::int32_t y, const float h_scroll,
                        const float v_scroll) const -> void {
        auto msg = std::make_unique<scroll_msg>();
        msg->position = position_t(x, y, this->width, this->height);
        msg->h_scroll = ifp16_t{h_scroll};
        msg->v_scroll = ifp16_t{v_scroll};
        msg->action_button = abs_enum_t<android_motionevent_buttons, std::uint32_t>{
            android_motionevent_buttons::AMOTION_EVENT_BUTTON_PRIMARY
        };
        this->send_control_msg(std::move(msg));
    }

    auto client::send_single_byte_control_msg(control_msg_type msg_type) const -> void {
        this->send_control_msg(std::make_unique<single_byte_msg>(msg_type));
    }
}
