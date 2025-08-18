//
// Created by ender on 25-3-11.
//

#ifndef CONTROL_MSG_HPP
#define CONTROL_MSG_HPP
#include <cstdint>
#include <string>
#include <vector>
#include <algorithm>
#include <array>
#include <boost/asio.hpp>

namespace scrcpy {
    namespace pointer_id {
        constexpr std::uint64_t MOUSE = -1;
        constexpr std::uint64_t GENERIC_FINGER = -2;
        constexpr std::uint64_t VIRTUAL_FINGER = -3;
    }

    enum class android_motionevent_action {
        /** Bit mask of the parts of the action code that are the action itself. */
        AMOTION_EVENT_ACTION_MASK = 0xff,

        /**
         * Bits in the action code that represent a pointer index, used with
         * AMOTION_EVENT_ACTION_POINTER_DOWN and AMOTION_EVENT_ACTION_POINTER_UP.  Shifting
         * down by AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT provides the actual pointer
         * index where the data for the pointer going up or down can be found.
         */
        AMOTION_EVENT_ACTION_POINTER_INDEX_MASK = 0xff00,

        /** A pressed gesture has started, the motion contains the initial starting location. */
        AMOTION_EVENT_ACTION_DOWN = 0,

        /**
         * A pressed gesture has finished, the motion contains the final release location
         * as well as any intermediate points since the last down or move event.
         */
        AMOTION_EVENT_ACTION_UP = 1,

        /**
         * A change has happened during a press gesture (between AMOTION_EVENT_ACTION_DOWN and
         * AMOTION_EVENT_ACTION_UP).  The motion contains the most recent point, as well as
         * any intermediate points since the last down or move event.
         */
        AMOTION_EVENT_ACTION_MOVE = 2,

        /**
         * The current gesture has been aborted.
         * You will not receive any more points in it.  You should treat this as
         * an up event, but not perform any action that you normally would.
         */
        AMOTION_EVENT_ACTION_CANCEL = 3,

        /**
         * A movement has happened outside of the normal bounds of the UI element.
         * This does not provide a full gesture, but only the initial location of the movement/touch.
         */
        AMOTION_EVENT_ACTION_OUTSIDE = 4,

        /**
         * A non-primary pointer has gone down.
         * The bits in AMOTION_EVENT_ACTION_POINTER_INDEX_MASK indicate which pointer changed.
         */
        AMOTION_EVENT_ACTION_POINTER_DOWN = 5,

        /**
         * A non-primary pointer has gone up.
         * The bits in AMOTION_EVENT_ACTION_POINTER_INDEX_MASK indicate which pointer changed.
         */
        AMOTION_EVENT_ACTION_POINTER_UP = 6,

        /**
         * A change happened but the pointer is not down (unlike AMOTION_EVENT_ACTION_MOVE).
         * The motion contains the most recent point, as well as any intermediate points since
         * the last hover move event.
         */
        AMOTION_EVENT_ACTION_HOVER_MOVE = 7,

        /**
         * The motion event contains relative vertical and/or horizontal scroll offsets.
         * Use getAxisValue to retrieve the information from AMOTION_EVENT_AXIS_VSCROLL
         * and AMOTION_EVENT_AXIS_HSCROLL.
         * The pointer may or may not be down when this event is dispatched.
         * This action is always delivered to the winder under the pointer, which
         * may not be the window currently touched.
         */
        AMOTION_EVENT_ACTION_SCROLL = 8,

        /** The pointer is not down but has entered the boundaries of a window or view. */
        AMOTION_EVENT_ACTION_HOVER_ENTER = 9,

        /** The pointer is not down but has exited the boundaries of a window or view. */
        AMOTION_EVENT_ACTION_HOVER_EXIT = 10,

        /* One or more buttons have been pressed. */
        AMOTION_EVENT_ACTION_BUTTON_PRESS = 11,

        /* One or more buttons have been released. */
        AMOTION_EVENT_ACTION_BUTTON_RELEASE = 12,
    };

    enum class control_msg_type {
        SC_CONTROL_MSG_TYPE_INJECT_KEYCODE,
        SC_CONTROL_MSG_TYPE_INJECT_TEXT,
        SC_CONTROL_MSG_TYPE_INJECT_TOUCH_EVENT,
        SC_CONTROL_MSG_TYPE_INJECT_SCROLL_EVENT,
        SC_CONTROL_MSG_TYPE_BACK_OR_SCREEN_ON,
        SC_CONTROL_MSG_TYPE_EXPAND_NOTIFICATION_PANEL,
        SC_CONTROL_MSG_TYPE_EXPAND_SETTINGS_PANEL,
        SC_CONTROL_MSG_TYPE_COLLAPSE_PANELS,
        SC_CONTROL_MSG_TYPE_GET_CLIPBOARD,
        SC_CONTROL_MSG_TYPE_SET_CLIPBOARD,
        SC_CONTROL_MSG_TYPE_SET_DISPLAY_POWER,
        SC_CONTROL_MSG_TYPE_ROTATE_DEVICE,
        SC_CONTROL_MSG_TYPE_UHID_CREATE,
        SC_CONTROL_MSG_TYPE_UHID_INPUT,
        SC_CONTROL_MSG_TYPE_UHID_DESTROY,
        SC_CONTROL_MSG_TYPE_OPEN_HARD_KEYBOARD_SETTINGS,
        SC_CONTROL_MSG_TYPE_START_APP,
        SC_CONTROL_MSG_TYPE_RESET_VIDEO,
    };

    enum class copy_key {
        SC_COPY_KEY_NONE,
        SC_COPY_KEY_COPY,
        SC_COPY_KEY_CUT,
    };

    enum class android_motionevent_buttons {
        /** primary */
        AMOTION_EVENT_BUTTON_PRIMARY = 1 << 0,
        /** secondary */
        AMOTION_EVENT_BUTTON_SECONDARY = 1 << 1,
        /** tertiary */
        AMOTION_EVENT_BUTTON_TERTIARY = 1 << 2,
        /** back */
        AMOTION_EVENT_BUTTON_BACK = 1 << 3,
        /** forward */
        AMOTION_EVENT_BUTTON_FORWARD = 1 << 4,
        AMOTION_EVENT_BUTTON_STYLUS_PRIMARY = 1 << 5,
        AMOTION_EVENT_BUTTON_STYLUS_SECONDARY = 1 << 6,
    };

    class dtype {
    public:
        virtual ~dtype() = default;

        /**
         * data to bytes in big-endian
         * @return byte sequence
         */
        virtual auto serialize() -> std::vector<std::byte> = 0;
    };

    class sizable {
    public:
        virtual ~sizable() = default;

        virtual auto size() const -> std::size_t = 0;
    };

    class fixed_size : public sizable {
    };

    class var_size : public sizable {
    };

    template<typename INT_TYPE, std::size_t BYTE_SIZE = sizeof(INT_TYPE)>
    class abs_int_t : public dtype, public fixed_size {
        static_assert(std::is_integral_v<INT_TYPE>);

    public:
        typedef INT_TYPE value_type;
        static constexpr std::size_t value_size = BYTE_SIZE;

        explicit abs_int_t(const INT_TYPE value) : value(value) {
        }

        explicit operator INT_TYPE() const {
            return value;
        }

        auto serialize() -> std::vector<std::byte> override {
            auto arr_ptr = reinterpret_cast<std::array<std::byte, BYTE_SIZE> *>(&value);
            std::vector<std::byte> buffer{BYTE_SIZE};
            std::reverse_copy(arr_ptr->begin(), arr_ptr->end(), buffer.begin());
            return buffer;
        }

        auto size() const -> std::size_t override {
            return BYTE_SIZE;
        }

        auto val() {
            return value;
        }

    private:
        INT_TYPE value{0};
    };

    template<typename FLOAT_TYPE, std::size_t BYTE_SIZE = sizeof(FLOAT_TYPE)>
    class abs_float_t final : public dtype, public fixed_size {
    public:
        explicit abs_float_t(const FLOAT_TYPE value) : value(value) {
        }

        explicit operator FLOAT_TYPE() const {
            return value;
        }

        auto serialize() -> std::vector<std::byte> override {
            auto arr_ptr = reinterpret_cast<std::array<std::byte, BYTE_SIZE> *>(&value);
            std::vector<std::byte> buffer{BYTE_SIZE};
            std::reverse_copy(arr_ptr->begin(), arr_ptr->end(), buffer.begin());
            return buffer;
        }

        auto size() const -> std::size_t override {
            return BYTE_SIZE;
        }

        auto val() {
            return value;
        }

    private:
        FLOAT_TYPE value{0.0};
    };

    class ufp16_t final : public abs_int_t<std::uint16_t> {
    public:
        explicit ufp16_t(const float value)
            : abs_int_t(float_to_u16fp(value)) {
        }

        static std::uint16_t float_to_u16fp(const float f) {
            if (not(f >= 0.0f && f <= 1.0f)) throw std::invalid_argument("invalid floating point value");
            std::uint32_t u = f * 0x1p16f;
            if (u >= 0xffff) {
                if (u != 0x10000) throw std::invalid_argument("float bit error");
                u = 0xffff;
            }
            return static_cast<uint16_t>(u);
        }
    };

    class ifp16_t final : public abs_int_t<std::int16_t> {
    public:
        explicit ifp16_t(const float value)
            : abs_int_t(float_to_i16fp(value)) {
        }

        static std::int16_t float_to_i16fp(const float f) {
            if (f < -1.0f or f > 1.0f) throw std::invalid_argument("invalid floating point value");
            std::int32_t i = f * 0x1p15f; // 2^15
            if (i < -0x8000) throw std::invalid_argument("float_to_i16fp underflow");
            if (i >= 0x7fff) {
                if (i != 0x8000) throw std::invalid_argument("float_to_i16fp overflow"); // for f == 1.0f
                i = 0x7fff;
            }
            return static_cast<std::int16_t>(i);
        }
    };

    template<typename ENUM_TYPE, typename BASE_INT_TYPE=std::uint8_t, std::size_t BYTE_SIZE = sizeof(BASE_INT_TYPE)>
    class abs_enum_t final : public abs_int_t<BASE_INT_TYPE, BYTE_SIZE> {
    public:
        explicit abs_enum_t(ENUM_TYPE value)
            : abs_int_t<BASE_INT_TYPE, BYTE_SIZE>(static_cast<BASE_INT_TYPE>(value)) {
        }
    };

    class control_msg {
    public:
        virtual ~control_msg() = 0;

        [[nodiscard]] virtual auto buf_size() const -> std::size_t = 0;

        virtual auto serialize() -> std::vector<std::byte> = 0;

        virtual auto join_buf(const std::vector<std::byte> &buf) -> void;

        virtual auto init_buf() -> std::vector<std::byte>;

    private:
        std::vector<std::byte>::iterator buf_it;
    };

    class single_byte_msg : public control_msg {
    public:
        explicit single_byte_msg(control_msg_type type);

        [[nodiscard]] auto buf_size() const -> std::size_t override;

        auto serialize() -> std::vector<std::byte> override;

    private:
        std::optional<abs_enum_t<control_msg_type> > msg_type;
    };

    class position_t final : public fixed_size, public dtype {
    public:
        position_t(std::int32_t x, std::int32_t y, std::uint16_t width, std::uint16_t height);

        ~position_t() override;

        auto size() const -> std::size_t override;

        auto serialize() -> std::vector<std::byte> override;

    private:
        abs_int_t<std::int32_t> x;
        abs_int_t<std::int32_t> y;

        abs_int_t<std::uint16_t> width;
        abs_int_t<std::uint16_t> height;
    };

    template<typename size_type=abs_int_t<std::int32_t> >
    class string_t final : public dtype, public var_size {
    public:
        explicit string_t(const std::string &value, const std::size_t max_string_size = 256) : value(value) {
            if (this->value.size() > max_string_size) {
                throw std::out_of_range(
                    std::format("string value too long: {}/{}", this->value.size(), max_string_size));
            }
        }

        auto serialize() -> std::vector<std::byte> override {
            std::vector<std::byte> buf;
            buf.resize(this->size());
            auto str_len = size_type{static_cast<typename size_type::value_type>(this->value.size())};
            std::copy_n(str_len.serialize().begin(), str_len.size(), buf.begin());
            std::copy_n(reinterpret_cast<const std::byte *>(this->value.c_str()), this->value.size(),
                        buf.begin() + str_len.size());
            return buf;
        }

        auto size() const -> std::size_t override {
            return this->value.size() + size_type::value_size;
        }

    private:
        std::string value;
    };

    class touch_msg final : public control_msg {
    public:
        [[nodiscard]] auto buf_size() const -> std::size_t override;

        auto serialize() -> std::vector<std::byte> override;

        std::optional<abs_enum_t<control_msg_type> > msg_type =
                abs_enum_t{control_msg_type::SC_CONTROL_MSG_TYPE_INJECT_TOUCH_EVENT};
        std::optional<abs_enum_t<android_motionevent_action> > action;
        std::optional<abs_int_t<std::uint64_t> > pointer_id;
        std::optional<position_t> position;
        std::optional<ufp16_t> pressure;
        std::optional<abs_enum_t<android_motionevent_buttons, std::uint32_t> > action_button;
        std::optional<abs_enum_t<android_motionevent_buttons, std::uint32_t> > buttons;
    };

    class text_msg final : public control_msg {
    public:
        explicit text_msg() {
        }

        auto serialize() -> std::vector<std::byte> override;

        [[nodiscard]] auto buf_size() const -> std::size_t override;

        std::optional<abs_enum_t<control_msg_type> > msg_type = abs_enum_t{
            control_msg_type::SC_CONTROL_MSG_TYPE_INJECT_TEXT
        };
        std::optional<string_t<> > text;
    };

    class start_app_msg final : public control_msg {
    public:
        [[nodiscard]] auto buf_size() const -> std::size_t override;

        auto serialize() -> std::vector<std::byte> override;

        std::optional<abs_enum_t<control_msg_type> > msg_type = abs_enum_t{
            control_msg_type::SC_CONTROL_MSG_TYPE_START_APP
        };
        std::optional<string_t<abs_int_t<std::uint8_t> > > app_name;
    };

    class scroll_msg final : public control_msg {
    public:
        [[nodiscard]] auto buf_size() const -> std::size_t override;

        auto serialize() -> std::vector<std::byte> override;

        std::optional<abs_enum_t<control_msg_type> > msg_type = abs_enum_t{
            control_msg_type::SC_CONTROL_MSG_TYPE_INJECT_SCROLL_EVENT
        };
        std::optional<position_t> position;
        std::optional<ifp16_t> h_scroll;
        std::optional<ifp16_t> v_scroll;
        std::optional<abs_enum_t<android_motionevent_buttons, std::uint32_t> > action_button;
    };

    class back_or_screen_on_msg final : public control_msg {
    public:
        [[nodiscard]] auto buf_size() const -> std::size_t override;

        auto serialize() -> std::vector<std::byte> override;

        std::optional<abs_enum_t<control_msg_type> > msg_type = abs_enum_t{
            control_msg_type::SC_CONTROL_MSG_TYPE_BACK_OR_SCREEN_ON
        };
        std::optional<abs_enum_t<android_motionevent_action> > action;
    };
}


#endif //CONTROL_MSG_HPP
