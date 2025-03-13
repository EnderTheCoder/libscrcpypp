//
// Created by ender on 25-3-11.
//

#include "control_msg.hpp"

namespace scrcpy {
    control_msg::~control_msg() = default;

    auto control_msg::join_buf(const std::vector<std::byte> &buf) -> void {
        std::copy_n(buf.begin(), buf.size(), buf_it);
        buf_it += static_cast<std::int64_t>(buf.size());
    }

    auto control_msg::init_buf() -> std::vector<std::byte> {
        std::vector<std::byte> buf(this->buf_size());
        this->buf_it = buf.begin();
        return buf;
    }

    single_byte_msg::single_byte_msg(const control_msg_type type) {
        this->msg_type = abs_enum_t{type};
    }

    auto single_byte_msg::buf_size() const -> std::size_t {
        return 1;
    }

    auto single_byte_msg::serialize() -> std::vector<std::byte> {
        auto buf = this->init_buf();
        this->join_buf(this->msg_type->serialize());
        return buf;
    }

    position_t::position_t(const std::int32_t x, const std::int32_t y, const std::uint16_t width,
                           const std::uint16_t height)
        : x(x), y(y), width(width), height(height) {
    }

    position_t::~position_t() = default;

    auto position_t::size() -> std::size_t {
        return 12;
    }

    auto position_t::serialize() -> std::vector<std::byte> {
        std::vector<std::byte> buf;
        buf.resize(this->size());
        std::copy_n(x.serialize().begin(), 4, buf.begin());
        std::copy_n(y.serialize().begin(), 4, buf.begin() + 4);
        std::copy_n(width.serialize().begin(), 2, buf.begin() + 8);
        std::copy_n(height.serialize().begin(), 2, buf.begin() + 10);
        return buf;
    }

    auto string_t::serialize() -> std::vector<std::byte> {
        std::vector<std::byte> buf;
        buf.resize(this->size());
        auto str_len = abs_int_t{static_cast<std::uint32_t>(this->value.size())};
        std::copy_n(str_len.serialize().begin(), 4, buf.begin());
        std::copy_n(reinterpret_cast<const std::byte *>(this->value.c_str()), this->value.size(),
                    buf.begin() + str_len.size());
        return buf;
    }

    auto string_t::size() -> std::size_t {
        return this->value.size() + 4;
    }

    std::size_t touch_msg::buf_size() const {
        return 32;
    }

    std::vector<std::byte> touch_msg::serialize() {
        auto buf = this->init_buf();
        this->join_buf(msg_type->serialize());
        this->join_buf(action->serialize());
        this->join_buf(pointer_id->serialize());
        this->join_buf(position->serialize());
        this->join_buf(pressure->serialize());
        this->join_buf(action_button->serialize());
        this->join_buf(buttons->serialize());
        return buf;
    }

    std::vector<std::byte> text_msg::serialize() {
        auto buf = single_byte_msg::serialize();
        buf.resize(buf.size() + this->text->size());
        std::copy_n(this->text->serialize().begin(), this->text->size(), buf.end());
        return buf;
    }
}
