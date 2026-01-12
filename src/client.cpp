//
// Created by ender on 25-2-15.
//
#include <client.hpp>
#include <boost/process/v2/stdio.hpp>
#include <boost/algorithm/string/trim.hpp>

namespace scrcpy {
    using process = boost::process::v2::process;
    using process_stdio = boost::process::v2::process_stdio;

    auto client::create_shared(std::string_view addr, std::uint16_t port) -> std::shared_ptr<client> {
        return std::make_shared<client>(addr, port);
    }

    client::client(const std::string_view addr, const std::uint16_t port) : addr(addr), port_(port) {
    }

    client::~client() {
        if (recv_enabled) {
            stop_recv();
        }
        if (config_packet != nullptr) {
            av_packet_free(&config_packet);
        }
        if (server_proc.has_value() && server_proc->running()) {
            server_proc->terminate();
            server_proc->wait();
        }
    }

    auto client::get_port() const -> std::uint16_t { return port_; }

    auto client::get_addr() const -> std::string_view { return addr; }

    auto client::connect() -> void {
        using boost::asio::ip::tcp;

        tcp::resolver resolver(ctx);
        const auto endpoints = resolver.resolve(addr, std::to_string(port_));

        if (this->video_socket != nullptr and video_socket->is_open()) {
            video_socket->close();
        }
        this->video_socket = std::make_shared<tcp::socket>(ctx);
        boost::asio::connect(*this->video_socket, endpoints);

        if (this->control_socket != nullptr and control_socket->is_open()) {
            control_socket->close();
        }
        this->control_socket = std::make_shared<tcp::socket>(ctx);
        boost::asio::connect(*this->control_socket, endpoints);

        try {
            std::array<char, 1> dummy_byte_buffer = {};
            boost::asio::read(*video_socket, boost::asio::buffer(dummy_byte_buffer));
            if (dummy_byte_buffer[0] != 0x00) {
                throw std::runtime_error(std::format("broken packet, expect 0x00 but got {:#x}.",
                                                     dummy_byte_buffer[0]));
            }
#ifdef _DEBUG
            std::cout << "successfully read dummy byte." << std::endl;
#endif
        }
        catch (std::exception& e) {
            throw std::runtime_error(std::format("error reading dummy byte: {}", e.what()));
        }
        std::array<char, 64> device_name_buffer = {};
        boost::asio::read(*video_socket, boost::asio::buffer(device_name_buffer));
        this->device_name = device_name_buffer.data();
#ifdef _DEBUG
        std::cout << "device name: " << device_name << std::endl;
#endif

        std::array<std::byte, 12> codec_meta_buffer = {};
        if (boost::asio::read(*video_socket, boost::asio::buffer(codec_meta_buffer)) != 12) {
            throw std::runtime_error("Incomplete codec metadata received.");
        }
        this->codec = std::string{reinterpret_cast<char*>(codec_meta_buffer.data()), 4};
        std::reverse(codec_meta_buffer.begin() + 4, codec_meta_buffer.begin() + 8);
        std::reverse(codec_meta_buffer.begin() + 8, codec_meta_buffer.end());
        this->width = *reinterpret_cast<std::uint32_t*>(codec_meta_buffer.data() + 4);
        this->height = *reinterpret_cast<std::uint32_t*>(codec_meta_buffer.data() + 8);
#ifdef _DEBUG
        std::cout << "video stream codec: " << this->codec << std::endl;
        std::cout << "video stream working at resolution: " << this->height << "x" << this->width << std::endl;
#endif
    }

    auto client::is_connected() const -> bool {
        return this->video_socket != nullptr and video_socket->is_open() and control_socket != nullptr and
            control_socket->is_open();
    }

    auto client::kill_remote_server(const std::filesystem::path& adb_bin, const std::string& device_serial) -> void {
        auto proc = process(ctx, adb_bin.c_str(),
                            {"-s", device_serial.c_str(), "shell", "killall", "-9", "app_process"});
        proc.wait();
    }

    auto client::remove_forward_rules(const std::filesystem::path& adb_bin, const std::string& device_serial) -> void {
        auto proc = process(ctx, adb_bin.c_str(),
                            {"-s", device_serial.c_str(), "forward", "--remove-all"});
        proc.wait();
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
            }
            catch (std::exception& e) {
                std::cerr << "recv stopped: " << e.what() << std::endl;
            }
        });
    }


    auto client::stop_recv() -> void {
        this->recv_enabled = false;
        this->recv_cancelled = true;

        if (this->video_socket != nullptr && this->video_socket->is_open()) {
            boost::system::error_code ec;
            this->video_socket->cancel(ec);
            this->video_socket->close(ec);
        }

        if (this->control_socket != nullptr && this->control_socket->is_open()) {
            boost::system::error_code ec;
            this->control_socket->cancel(ec);
            this->control_socket->close(ec);
        }

        if (this->recv_handle.joinable()) {
            this->recv_handle.join();
        }
    }

    auto client::is_recv_enabled() -> bool {
        return this->recv_enabled;
    }


    auto client::set_frame_consumer(const std::function<void(std::shared_ptr<frame>)>& consumer) -> void {
        this->consumer_ = consumer;
    }

    auto client::frames() -> std::vector<std::shared_ptr<frame>> {
        std::lock_guard lock(this->frame_mutex);
        if (frame_queue.empty()) {
            return {};
        }
        std::vector<std::shared_ptr<frame>> frames = {};
        frames.insert(frames.end(), frame_queue.begin(), frame_queue.end());
        frame_queue.clear();
        return frames;
    }

    auto client::video_size() -> std::tuple<std::uint64_t, std::uint64_t> {
        return {width, height};
    }

    auto client::read_forward(const std::filesystem::path& adb_bin) -> std::vector<std::array<std::string, 3>> {
        using namespace boost::process;
        boost::asio::io_context ctx;
        boost::asio::readable_pipe rp(ctx);
        process list_proc(ctx, adb_bin.string(), {"forward", "--list"}, process_stdio{{}, rp, {}});
        list_proc.wait();
        if (auto ext_c = list_proc.exit_code(); ext_c != 0) {
            throw std::runtime_error(
                std::format("Failed to list forward list: adb process ended unexpectedly with exit code {}", ext_c));
        }
        const auto lines = read_lines_from_rp(rp);
        std::vector<std::array<std::string, 3>> forward_list;
        for (const auto& line : lines) {
            using std::operator ""sv;

            auto item = std::array<std::string, 3>{};
            for (const auto [idx, part] : std::views::split(line, " "sv) | std::views::enumerate) {
                item.at(idx) = std::string_view(part);
            }
            forward_list.emplace_back(item);
        }
        return forward_list;
    }

    std::optional<std::string> client::forward_list_contains_tcp_port(
        const std::filesystem::path& adb_bin,
        const std::uint16_t port) {
        for (const auto& [serial, local, remote] : read_forward(adb_bin)) {
            if (local.contains(std::format("tcp:{}", port))) {
                return serial;
            }
        }
        return std::nullopt;
    }

    auto client::list_dev_serials(const std::filesystem::path& adb_bin) -> std::vector<std::string> {
        using namespace boost::process;
        using namespace boost::asio;
        io_context ctx;
        readable_pipe rp(ctx);
        using std::operator ""sv;
        process list_proc(ctx, adb_bin.string(), {"devices"}, process_stdio{{}, rp, {}});
        auto sig_start = false;
        std::vector<std::string> serials;
        list_proc.wait();
        for (const auto lines = read_lines_from_rp(rp); const auto& line : lines) {
            if (sig_start and line.contains("device")) {
                for (const auto [s_begin, s_end] : std::views::split(line, "\t"sv)) {
                    auto serial = std::string_view(s_begin, s_end);
                    serials.emplace_back(serial);
                    break;
                }
            }
            else if (line == "List of devices attached") {
                sig_start = true;
            }
        }
        return serials;
    }

    auto client::run_recv() -> void {
        try {
            recv_enabled = true;
            recv_cancelled = false;

            while (true) {
                if (!recv_enabled || recv_cancelled) {
                    break;
                }

                if (!this->server_alive()) {
                    throw std::runtime_error("Server died too early.");
                }

                std::array<std::uint8_t, 12> frame_header_buffer{};

                boost::system::error_code ec;
                size_t bytes_read = boost::asio::read(*video_socket,
                                                      boost::asio::buffer(frame_header_buffer),
                                                      ec);

                if (ec == boost::asio::error::operation_aborted) {
#ifdef _DEBUG
                    std::cout << "Read operation cancelled." << std::endl;
#endif
                    break;
                }
                if (ec == boost::asio::error::eof || ec == boost::asio::error::connection_reset) {
#ifdef _DEBUG
                    std::cout << "Connection closed by peer." << std::endl;
#endif
                    break;
                }
                if (ec) {
                    throw boost::system::system_error(ec, "Failed to read frame header");
                }

                if (bytes_read != 12) {
                    throw std::runtime_error("Incomplete frame header received.");
                }

                const bool config_flag = frame_header_buffer.at(0) >> 7 & 0x01;
                const bool keyframe_flag = frame_header_buffer.at(0) >> 6 & 0x01;
                std::reverse(frame_header_buffer.begin(), frame_header_buffer.begin() + 8);
                frame_header_buffer.at(7) <<= 2;
                const auto pts = *reinterpret_cast<std::uint64_t*>(frame_header_buffer.data());
                std::reverse(frame_header_buffer.begin() + 8, frame_header_buffer.end());
                const auto packet_size = *reinterpret_cast<std::uint32_t*>(frame_header_buffer.data() + 8);

                AVPacket* packet = av_packet_alloc();
                if (packet == nullptr) {
                    throw std::runtime_error("av_packet_alloc failed");
                }
                if (av_new_packet(packet, static_cast<std::int32_t>(packet_size))) {
                    av_packet_free(&packet);
                    throw std::runtime_error("failed to allocate packet memory");
                }

                bytes_read = boost::asio::read(*this->video_socket,
                                               boost::asio::buffer(packet->data, packet_size),
                                               ec);

                if (ec == boost::asio::error::operation_aborted) {
                    av_packet_free(&packet);
#ifdef _DEBUG
                    std::cout << "Read operation cancelled during frame data read." << std::endl;
#endif
                    break;
                }
                if (ec == boost::asio::error::eof || ec == boost::asio::error::connection_reset) {
                    av_packet_free(&packet);
#ifdef _DEBUG
                    std::cout << "Connection closed by peer during frame data read." << std::endl;
#endif
                    break;
                }
                if (ec) {
                    av_packet_free(&packet);
                    throw boost::system::system_error(ec, "Failed to read frame data");
                }

                packet->size = static_cast<std::int32_t>(packet_size);

                if (bytes_read != packet_size) {
                    av_packet_free(&packet);
                    if (this->config_packet != nullptr) {
                        av_packet_free(&this->config_packet);
                    }
                    std::cerr << "end of video stream" << std::endl;
                    this->recv_enabled = false;
                    boost::system::error_code close_ec;
                    this->video_socket->close(close_ec);
                    if (this->consumer_.has_value()) {
                        this->consumer_.value()(nullptr);
                    }
                    return;
                }

                // 处理包数据...
                if (config_flag) {
                    packet->pts = AV_NOPTS_VALUE;
                }
                else {
                    packet->pts = static_cast<std::int64_t>(pts);
                }

                if (keyframe_flag) {
                    packet->flags |= AV_PKT_FLAG_KEY;
                }

                packet->dts = packet->pts;
                if (config_flag) {
                    config_packet = packet;
                }
                else if (config_packet != nullptr) {
                    if (av_grow_packet(packet, config_packet->size)) {
                        av_packet_free(&packet);
                        throw std::runtime_error("failed to grow packet");
                    }
                    memmove(packet->data + config_packet->size, packet->data, packet->size);
                    memcpy(packet->data, config_packet->data, config_packet->size);
                    av_packet_free(&config_packet);
                    config_packet = nullptr;
                }

                const auto frames = decoder.decode(packet);
                if (frames.empty()) {
                    continue;
                }

                if (this->consumer_.has_value()) {
                    for (const auto& frame : frames) {
                        this->consumer_.value()(frame);
                    }
                    continue;
                }

                frame_mutex.lock();
                std::ranges::copy(frames, std::back_inserter(frame_queue));
                frame_mutex.unlock();
            }
        }
        catch (const boost::system::system_error& e) {
            if (e.code() == boost::asio::error::operation_aborted ||
                e.code() == boost::asio::error::eof ||
                e.code() == boost::asio::error::connection_reset) {
                std::cout << "Network operation cancelled or connection closed: " << e.what() << std::endl;
            }
            else {
                std::cerr << "Network error in recv thread: " << e.what() << std::endl;
                throw;
            }
        }
        catch (const std::exception& e) {
            std::cerr << "Error in recv thread: " << e.what() << std::endl;
            throw;
        }
        catch (...) {
            std::cerr << "Unknown error in recv thread" << std::endl;
            throw;
        }

        this->recv_enabled = false;
        this->recv_cancelled = true;
    }

    auto client::deploy(const std::filesystem::path& adb_bin,
                        const std::filesystem::path& scrcpy_jar_bin,
                        const std::string& scrcpy_server_version, const std::uint16_t port,
                        const std::optional<std::string>& device_serial,
                        const std::optional<std::uint16_t>& max_size) -> void {
        //adb shell CLASSPATH=/sdcard/scrcpy-server.jar app_process / com.genymobile.scrcpy.Server 3.1 tunnel_forward=true cleanup=false audio=false control=false max_size=1920
        using namespace boost::process;
        using namespace boost::asio;
        auto adb_exec = adb_bin.string();
        if (not std::filesystem::exists(adb_exec)) {
            throw std::system_error{std::make_error_code(std::errc::no_such_file_or_directory), "Adb path not exists."};
        }
        if (not std::filesystem::exists(scrcpy_jar_bin)) {
            throw std::system_error{
                std::make_error_code(std::errc::no_such_file_or_directory), "Scrcpy jar path not exists."
            };
        }
        std::string serial;
        if (device_serial.has_value()) {
            serial = device_serial.value();
        }
        else {
            readable_pipe serial_rp(ctx);

            auto serial_proc = process(ctx, adb_exec, {"get-serialno"}, process_stdio{{}, serial_rp, {}});
            serial_proc.wait();
            if (serial_proc.exit_code() != 0) {
                throw std::runtime_error("failed to get adb device serialno");
            }

            serial = read_from_rp(serial_rp);
            boost::algorithm::trim(serial);
        }

        if (server_proc.has_value() and server_proc->running()) {
            std::cerr << std::format("[{}]scrcpy server it already running, terminating...", serial) << std::endl;
            server_proc->terminate();
            std::cerr << std::format("[{}]scrcpy server terminated", serial) << std::endl;
        }

        process upload_proc(ctx, adb_exec, {
                                "-s", serial, "push", scrcpy_jar_bin.string(), "/sdcard/scrcpy-server.jar"
                            });
        upload_proc.wait();
        if (upload_proc.exit_code() != 0) {
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
        }
        else {
            readable_pipe forward_rp(ctx);
            process forward_proc(ctx, adb_exec,
                                 {"-s", serial, "forward", std::format("tcp:{}", port), "localabstract:scrcpy"},
                                 process_stdio{{}, forward_rp, {}});
            forward_proc.wait();

            if (forward_proc.exit_code() != 0) {
                auto reason = read_from_rp(forward_rp);
                throw std::runtime_error(std::format("error forwarding scrcpy to local tcp port: {}", reason));
            }
        }

        this->server_rp = readable_pipe(ctx);
        auto param_max_size = max_size.has_value() ? std::format("max_size={}", max_size.value()) : "";
        this->server_proc = process{
            ctx, adb_exec,
            {
                "-s", serial, "shell", "CLASSPATH=/sdcard/scrcpy-server.jar", "app_process", "/",
                "com.genymobile.scrcpy.Server",
                scrcpy_server_version, "tunnel_forward=true", "cleanup=true", "video=true", "audio=false",
                "control=true", param_max_size
            },
            process_stdio{{}, server_rp.value(), {}}
        };

        bool output_received = false;
        auto start_time = std::chrono::steady_clock::now();
        while (true) {
            constexpr int timeout_ms = 10000;
            if (auto elapsed = std::chrono::steady_clock::now() - start_time;
                std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() > timeout_ms) {
                server_proc->terminate();
                throw std::runtime_error("server startup timed out (10s)");
            }

            if (not server_proc->running()) {
                int exit_code = server_proc->exit_code();
                throw std::runtime_error(std::format("server process exited unexpectedly (code: {})", exit_code));
            }

            // todo: fix reading
            if (auto first_line = read_first_line_from_rp(server_rp.value()); not first_line.empty() and first_line.
                contains("[server]")) {
                output_received = true;
                break;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }

        if (!output_received) {
            if (server_proc.has_value()) server_proc->terminate();
            throw std::runtime_error("failed to get server startup confirmation");
        }
    }

    auto client::terminate() -> void {
        if (this->server_proc.has_value() and this->server_proc->running()) {
            this->server_proc->terminate();
        }
    }

    auto client::server_alive() -> bool {
        return this->server_proc.has_value() and this->server_proc->running();
    }

    auto client::send_control_msg(const std::shared_ptr<control_msg>& msg) const -> void {
        auto buffer = msg->serialize();
        this->control_socket->send(boost::asio::buffer(buffer, buffer.size()));
    }

    auto client::get_server_dbg_logs() -> std::vector<std::string> {
        std::vector<std::string> dbg_logs;
        using namespace boost::asio;
        std::string line;
        while (this->server_rp->is_open()) {
            read_until(this->server_rp.value(), dynamic_buffer(line), '\n');
            if (!line.empty()) {
                if (!line.empty() && line.back() == '\n') {
                    line.pop_back();
                }
                if (!line.empty() && line.back() == '\r') {
                    line.pop_back();
                }

                if (!line.empty()) {
                    dbg_logs.push_back(line);
                    break;
                }
                line.clear();
            }
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
        auto& [x0, y0] = begin;
        auto& [x1, y1] = end;

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

    auto client::text(const std::string& text) const -> void {
        auto msg = std::make_unique<text_msg>();
        msg->text = string_t{text, 300};
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


    auto client::start_app(const std::string& app_name) const -> void {
        auto msg = std::make_unique<start_app_msg>();
        msg->app_name = string_t<abs_int_t<std::uint8_t>>{app_name};
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


    auto client::inject_keycode(const android_keycode keycode, const std::uint32_t repeat,
                                const android_metastate metastate) const -> void {
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

    auto client::read_first_line_from_rp(boost::asio::readable_pipe& rp) -> std::string {
        boost::system::error_code ec;
        std::string buffer;

        boost::asio::read_until(rp, boost::asio::dynamic_buffer(buffer), '\n', ec);

        if (not(ec.value() == 0 || ec == boost::asio::error::eof ||
            ec == boost::asio::error::broken_pipe ||
            ec == boost::asio::error::not_found)) {
            throw boost::system::system_error(ec);
        }

        if (const auto pos = buffer.find('\n'); pos != std::string::npos) {
            std::string line = buffer.substr(0, pos);
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            return line;
        }

        return buffer;
    }


    auto client::read_lines_from_rp(boost::asio::readable_pipe& rp) -> std::vector<std::string> {
        std::vector<std::string> lines;
        boost::system::error_code ec;

        std::string buffer;

        while (true) {
            // 检查缓冲区中是否还有未处理的数据
            std::size_t pos = 0;
            std::size_t found;

            // 先处理缓冲区中已有的数据
            while ((found = buffer.find('\n', pos)) != std::string::npos) {
                std::string line = buffer.substr(pos, found - pos);

                if (!line.empty() && line.back() == '\r') {
                    line.pop_back();
                }

                lines.push_back(line);
                pos = found + 1;
            }

            // 移除已处理的数据
            if (pos > 0) {
                buffer.erase(0, pos);
            }

            // 检查是否还有数据需要处理
            if (!buffer.empty() && (ec == boost::asio::error::eof || ec == boost::asio::error::not_found)) {
                if (buffer.back() == '\r') {
                    buffer.pop_back();
                }
                if (!buffer.empty()) {
                    lines.push_back(buffer);
                }
                break;
            }

            // 读取新数据
            std::string temp_buffer;
            const std::size_t n = boost::asio::read_until(
                rp,
                boost::asio::dynamic_buffer(temp_buffer),
                '\n',
                ec
            );

            if (n > 0) {
                // 将新读取的数据添加到缓冲区
                buffer.append(temp_buffer.substr(0, n));

                // 保留剩余未处理的数据
                if (n < temp_buffer.size()) {
                    buffer.append(temp_buffer.substr(n));
                }
            }
            else if (ec) {
                // 处理错误情况
                if (ec == boost::asio::error::eof || ec == boost::asio::error::not_found) {
                    if (!buffer.empty()) {
                        if (buffer.back() == '\r') {
                            buffer.pop_back();
                        }
                        if (!buffer.empty()) {
                            lines.push_back(buffer);
                        }
                    }
                }
                break;
            }
        }

        // 移除最后的空行
        if (!lines.empty() && lines.back().empty()) {
            lines.pop_back();
        }

        return lines;
    }


    auto client::read_from_rp(boost::asio::readable_pipe& rp) -> std::string {
        std::string result;
        boost::system::error_code ec;
        std::string buffer;

        while (true) {
            std::string temp_buffer;

            const std::size_t n = boost::asio::read_until(
                rp,
                boost::asio::dynamic_buffer(temp_buffer),
                '\n',
                ec
            );

            if (n > 0) {
                buffer.append(temp_buffer);
            }

            if (ec) {
                if (ec == boost::asio::error::eof ||
                    ec == boost::asio::error::broken_pipe ||
                    ec == boost::asio::error::not_found) {
                    if (!buffer.empty()) {
                        result.append(buffer);
                    }
                }
                else {
                    throw boost::system::system_error(ec);
                }
                break;
            }
        }

        return result;
    }


    auto client::send_single_byte_control_msg(control_msg_type msg_type) const -> void {
        this->send_control_msg(std::make_unique<single_byte_msg>(msg_type));
    }
}
