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

    /**
     * Key codes.
     */
    enum class android_keycode : std::uint32_t {
        /** Unknown key code. */
        AKEYCODE_UNKNOWN = 0,
        /** Soft Left key.
         * Usually situated below the display on phones and used as a multi-function
         * feature key for selecting a software defined function shown on the bottom left
         * of the display. */
        AKEYCODE_SOFT_LEFT = 1,
        /** Soft Right key.
         * Usually situated below the display on phones and used as a multi-function
         * feature key for selecting a software defined function shown on the bottom right
         * of the display. */
        AKEYCODE_SOFT_RIGHT = 2,
        /** Home key.
         * This key is handled by the framework and is never delivered to applications. */
        AKEYCODE_HOME = 3,
        /** Back key. */
        AKEYCODE_BACK = 4,
        /** Call key. */
        AKEYCODE_CALL = 5,
        /** End Call key. */
        AKEYCODE_ENDCALL = 6,
        /** '0' key. */
        AKEYCODE_0 = 7,
        /** '1' key. */
        AKEYCODE_1 = 8,
        /** '2' key. */
        AKEYCODE_2 = 9,
        /** '3' key. */
        AKEYCODE_3 = 10,
        /** '4' key. */
        AKEYCODE_4 = 11,
        /** '5' key. */
        AKEYCODE_5 = 12,
        /** '6' key. */
        AKEYCODE_6 = 13,
        /** '7' key. */
        AKEYCODE_7 = 14,
        /** '8' key. */
        AKEYCODE_8 = 15,
        /** '9' key. */
        AKEYCODE_9 = 16,
        /** '*' key. */
        AKEYCODE_STAR = 17,
        /** '#' key. */
        AKEYCODE_POUND = 18,
        /** Directional Pad Up key.
         * May also be synthesized from trackball motions. */
        AKEYCODE_DPAD_UP = 19,
        /** Directional Pad Down key.
         * May also be synthesized from trackball motions. */
        AKEYCODE_DPAD_DOWN = 20,
        /** Directional Pad Left key.
         * May also be synthesized from trackball motions. */
        AKEYCODE_DPAD_LEFT = 21,
        /** Directional Pad Right key.
         * May also be synthesized from trackball motions. */
        AKEYCODE_DPAD_RIGHT = 22,
        /** Directional Pad Center key.
         * May also be synthesized from trackball motions. */
        AKEYCODE_DPAD_CENTER = 23,
        /** Volume Up key.
         * Adjusts the speaker volume up. */
        AKEYCODE_VOLUME_UP = 24,
        /** Volume Down key.
         * Adjusts the speaker volume down. */
        AKEYCODE_VOLUME_DOWN = 25,
        /** Power key. */
        AKEYCODE_POWER = 26,
        /** Camera key.
         * Used to launch a camera application or take pictures. */
        AKEYCODE_CAMERA = 27,
        /** Clear key. */
        AKEYCODE_CLEAR = 28,
        /** 'A' key. */
        AKEYCODE_A = 29,
        /** 'B' key. */
        AKEYCODE_B = 30,
        /** 'C' key. */
        AKEYCODE_C = 31,
        /** 'D' key. */
        AKEYCODE_D = 32,
        /** 'E' key. */
        AKEYCODE_E = 33,
        /** 'F' key. */
        AKEYCODE_F = 34,
        /** 'G' key. */
        AKEYCODE_G = 35,
        /** 'H' key. */
        AKEYCODE_H = 36,
        /** 'I' key. */
        AKEYCODE_I = 37,
        /** 'J' key. */
        AKEYCODE_J = 38,
        /** 'K' key. */
        AKEYCODE_K = 39,
        /** 'L' key. */
        AKEYCODE_L = 40,
        /** 'M' key. */
        AKEYCODE_M = 41,
        /** 'N' key. */
        AKEYCODE_N = 42,
        /** 'O' key. */
        AKEYCODE_O = 43,
        /** 'P' key. */
        AKEYCODE_P = 44,
        /** 'Q' key. */
        AKEYCODE_Q = 45,
        /** 'R' key. */
        AKEYCODE_R = 46,
        /** 'S' key. */
        AKEYCODE_S = 47,
        /** 'T' key. */
        AKEYCODE_T = 48,
        /** 'U' key. */
        AKEYCODE_U = 49,
        /** 'V' key. */
        AKEYCODE_V = 50,
        /** 'W' key. */
        AKEYCODE_W = 51,
        /** 'X' key. */
        AKEYCODE_X = 52,
        /** 'Y' key. */
        AKEYCODE_Y = 53,
        /** 'Z' key. */
        AKEYCODE_Z = 54,
        /** ',' key. */
        AKEYCODE_COMMA = 55,
        /** '.' key. */
        AKEYCODE_PERIOD = 56,
        /** Left Alt modifier key. */
        AKEYCODE_ALT_LEFT = 57,
        /** Right Alt modifier key. */
        AKEYCODE_ALT_RIGHT = 58,
        /** Left Shift modifier key. */
        AKEYCODE_SHIFT_LEFT = 59,
        /** Right Shift modifier key. */
        AKEYCODE_SHIFT_RIGHT = 60,
        /** Tab key. */
        AKEYCODE_TAB = 61,
        /** Space key. */
        AKEYCODE_SPACE = 62,
        /** Symbol modifier key.
         * Used to enter alternate symbols. */
        AKEYCODE_SYM = 63,
        /** Explorer special function key.
         * Used to launch a browser application. */
        AKEYCODE_EXPLORER = 64,
        /** Envelope special function key.
         * Used to launch a mail application. */
        AKEYCODE_ENVELOPE = 65,
        /** Enter key. */
        AKEYCODE_ENTER = 66,
        /** Backspace key.
         * Deletes characters before the insertion point, unlike {@link AKEYCODE_FORWARD_DEL}. */
        AKEYCODE_DEL = 67,
        /** '`' (backtick) key. */
        AKEYCODE_GRAVE = 68,
        /** '-'. */
        AKEYCODE_MINUS = 69,
        /** '=' key. */
        AKEYCODE_EQUALS = 70,
        /** '[' key. */
        AKEYCODE_LEFT_BRACKET = 71,
        /** ']' key. */
        AKEYCODE_RIGHT_BRACKET = 72,
        /** '\' key. */
        AKEYCODE_BACKSLASH = 73,
        /** ';' key. */
        AKEYCODE_SEMICOLON = 74,
        /** ''' (apostrophe) key. */
        AKEYCODE_APOSTROPHE = 75,
        /** '/' key. */
        AKEYCODE_SLASH = 76,
        /** '@' key. */
        AKEYCODE_AT = 77,
        /** Number modifier key.
         * Used to enter numeric symbols.
         * This key is not {@link AKEYCODE_NUM_LOCK}; it is more like {@link AKEYCODE_ALT_LEFT}. */
        AKEYCODE_NUM = 78,
        /** Headset Hook key.
         * Used to hang up calls and stop media. */
        AKEYCODE_HEADSETHOOK = 79,
        /** Camera Focus key.
         * Used to focus the camera. */
        AKEYCODE_FOCUS = 80,
        /** '+' key. */
        AKEYCODE_PLUS = 81,
        /** Menu key. */
        AKEYCODE_MENU = 82,
        /** Notification key. */
        AKEYCODE_NOTIFICATION = 83,
        /** Search key. */
        AKEYCODE_SEARCH = 84,
        /** Play/Pause media key. */
        AKEYCODE_MEDIA_PLAY_PAUSE = 85,
        /** Stop media key. */
        AKEYCODE_MEDIA_STOP = 86,
        /** Play Next media key. */
        AKEYCODE_MEDIA_NEXT = 87,
        /** Play Previous media key. */
        AKEYCODE_MEDIA_PREVIOUS = 88,
        /** Rewind media key. */
        AKEYCODE_MEDIA_REWIND = 89,
        /** Fast Forward media key. */
        AKEYCODE_MEDIA_FAST_FORWARD = 90,
        /** Mute key.
         * Mutes the microphone, unlike {@link AKEYCODE_VOLUME_MUTE}. */
        AKEYCODE_MUTE = 91,
        /** Page Up key. */
        AKEYCODE_PAGE_UP = 92,
        /** Page Down key. */
        AKEYCODE_PAGE_DOWN = 93,
        /** Picture Symbols modifier key.
         * Used to switch symbol sets (Emoji, Kao-moji). */
        AKEYCODE_PICTSYMBOLS = 94,
        /** Switch Charset modifier key.
         * Used to switch character sets (Kanji, Katakana). */
        AKEYCODE_SWITCH_CHARSET = 95,
        /** A Button key.
         * On a game controller, the A button should be either the button labeled A
         * or the first button on the bottom row of controller buttons. */
        AKEYCODE_BUTTON_A = 96,
        /** B Button key.
         * On a game controller, the B button should be either the button labeled B
         * or the second button on the bottom row of controller buttons. */
        AKEYCODE_BUTTON_B = 97,
        /** C Button key.
         * On a game controller, the C button should be either the button labeled C
         * or the third button on the bottom row of controller buttons. */
        AKEYCODE_BUTTON_C = 98,
        /** X Button key.
         * On a game controller, the X button should be either the button labeled X
         * or the first button on the upper row of controller buttons. */
        AKEYCODE_BUTTON_X = 99,
        /** Y Button key.
         * On a game controller, the Y button should be either the button labeled Y
         * or the second button on the upper row of controller buttons. */
        AKEYCODE_BUTTON_Y = 100,
        /** Z Button key.
         * On a game controller, the Z button should be either the button labeled Z
         * or the third button on the upper row of controller buttons. */
        AKEYCODE_BUTTON_Z = 101,
        /** L1 Button key.
         * On a game controller, the L1 button should be either the button labeled L1 (or L)
         * or the top left trigger button. */
        AKEYCODE_BUTTON_L1 = 102,
        /** R1 Button key.
         * On a game controller, the R1 button should be either the button labeled R1 (or R)
         * or the top right trigger button. */
        AKEYCODE_BUTTON_R1 = 103,
        /** L2 Button key.
         * On a game controller, the L2 button should be either the button labeled L2
         * or the bottom left trigger button. */
        AKEYCODE_BUTTON_L2 = 104,
        /** R2 Button key.
         * On a game controller, the R2 button should be either the button labeled R2
         * or the bottom right trigger button. */
        AKEYCODE_BUTTON_R2 = 105,
        /** Left Thumb Button key.
         * On a game controller, the left thumb button indicates that the left (or only)
         * joystick is pressed. */
        AKEYCODE_BUTTON_THUMBL = 106,
        /** Right Thumb Button key.
         * On a game controller, the right thumb button indicates that the right
         * joystick is pressed. */
        AKEYCODE_BUTTON_THUMBR = 107,
        /** Start Button key.
         * On a game controller, the button labeled Start. */
        AKEYCODE_BUTTON_START = 108,
        /** Select Button key.
         * On a game controller, the button labeled Select. */
        AKEYCODE_BUTTON_SELECT = 109,
        /** Mode Button key.
         * On a game controller, the button labeled Mode. */
        AKEYCODE_BUTTON_MODE = 110,
        /** Escape key. */
        AKEYCODE_ESCAPE = 111,
        /** Forward Delete key.
         * Deletes characters ahead of the insertion point, unlike {@link AKEYCODE_DEL}. */
        AKEYCODE_FORWARD_DEL = 112,
        /** Left Control modifier key. */
        AKEYCODE_CTRL_LEFT = 113,
        /** Right Control modifier key. */
        AKEYCODE_CTRL_RIGHT = 114,
        /** Caps Lock key. */
        AKEYCODE_CAPS_LOCK = 115,
        /** Scroll Lock key. */
        AKEYCODE_SCROLL_LOCK = 116,
        /** Left Meta modifier key. */
        AKEYCODE_META_LEFT = 117,
        /** Right Meta modifier key. */
        AKEYCODE_META_RIGHT = 118,
        /** Function modifier key. */
        AKEYCODE_FUNCTION = 119,
        /** System Request / Print Screen key. */
        AKEYCODE_SYSRQ = 120,
        /** Break / Pause key. */
        AKEYCODE_BREAK = 121,
        /** Home Movement key.
         * Used for scrolling or moving the cursor around to the start of a line
         * or to the top of a list. */
        AKEYCODE_MOVE_HOME = 122,
        /** End Movement key.
         * Used for scrolling or moving the cursor around to the end of a line
         * or to the bottom of a list. */
        AKEYCODE_MOVE_END = 123,
        /** Insert key.
         * Toggles insert / overwrite edit mode. */
        AKEYCODE_INSERT = 124,
        /** Forward key.
         * Navigates forward in the history stack.  Complement of {@link AKEYCODE_BACK}. */
        AKEYCODE_FORWARD = 125,
        /** Play media key. */
        AKEYCODE_MEDIA_PLAY = 126,
        /** Pause media key. */
        AKEYCODE_MEDIA_PAUSE = 127,
        /** Close media key.
         * May be used to close a CD tray, for example. */
        AKEYCODE_MEDIA_CLOSE = 128,
        /** Eject media key.
         * May be used to eject a CD tray, for example. */
        AKEYCODE_MEDIA_EJECT = 129,
        /** Record media key. */
        AKEYCODE_MEDIA_RECORD = 130,
        /** F1 key. */
        AKEYCODE_F1 = 131,
        /** F2 key. */
        AKEYCODE_F2 = 132,
        /** F3 key. */
        AKEYCODE_F3 = 133,
        /** F4 key. */
        AKEYCODE_F4 = 134,
        /** F5 key. */
        AKEYCODE_F5 = 135,
        /** F6 key. */
        AKEYCODE_F6 = 136,
        /** F7 key. */
        AKEYCODE_F7 = 137,
        /** F8 key. */
        AKEYCODE_F8 = 138,
        /** F9 key. */
        AKEYCODE_F9 = 139,
        /** F10 key. */
        AKEYCODE_F10 = 140,
        /** F11 key. */
        AKEYCODE_F11 = 141,
        /** F12 key. */
        AKEYCODE_F12 = 142,
        /** Num Lock key.
         * This is the Num Lock key; it is different from {@link AKEYCODE_NUM}.
         * This key alters the behavior of other keys on the numeric keypad. */
        AKEYCODE_NUM_LOCK = 143,
        /** Numeric keypad '0' key. */
        AKEYCODE_NUMPAD_0 = 144,
        /** Numeric keypad '1' key. */
        AKEYCODE_NUMPAD_1 = 145,
        /** Numeric keypad '2' key. */
        AKEYCODE_NUMPAD_2 = 146,
        /** Numeric keypad '3' key. */
        AKEYCODE_NUMPAD_3 = 147,
        /** Numeric keypad '4' key. */
        AKEYCODE_NUMPAD_4 = 148,
        /** Numeric keypad '5' key. */
        AKEYCODE_NUMPAD_5 = 149,
        /** Numeric keypad '6' key. */
        AKEYCODE_NUMPAD_6 = 150,
        /** Numeric keypad '7' key. */
        AKEYCODE_NUMPAD_7 = 151,
        /** Numeric keypad '8' key. */
        AKEYCODE_NUMPAD_8 = 152,
        /** Numeric keypad '9' key. */
        AKEYCODE_NUMPAD_9 = 153,
        /** Numeric keypad '/' key (for division). */
        AKEYCODE_NUMPAD_DIVIDE = 154,
        /** Numeric keypad '*' key (for multiplication). */
        AKEYCODE_NUMPAD_MULTIPLY = 155,
        /** Numeric keypad '-' key (for subtraction). */
        AKEYCODE_NUMPAD_SUBTRACT = 156,
        /** Numeric keypad '+' key (for addition). */
        AKEYCODE_NUMPAD_ADD = 157,
        /** Numeric keypad '.' key (for decimals or digit grouping). */
        AKEYCODE_NUMPAD_DOT = 158,
        /** Numeric keypad ',' key (for decimals or digit grouping). */
        AKEYCODE_NUMPAD_COMMA = 159,
        /** Numeric keypad Enter key. */
        AKEYCODE_NUMPAD_ENTER = 160,
        /** Numeric keypad '=' key. */
        AKEYCODE_NUMPAD_EQUALS = 161,
        /** Numeric keypad '(' key. */
        AKEYCODE_NUMPAD_LEFT_PAREN = 162,
        /** Numeric keypad ')' key. */
        AKEYCODE_NUMPAD_RIGHT_PAREN = 163,
        /** Volume Mute key.
         * Mutes the speaker, unlike {@link AKEYCODE_MUTE}.
         * This key should normally be implemented as a toggle such that the first press
         * mutes the speaker and the second press restores the original volume. */
        AKEYCODE_VOLUME_MUTE = 164,
        /** Info key.
         * Common on TV remotes to show additional information related to what is
         * currently being viewed. */
        AKEYCODE_INFO = 165,
        /** Channel up key.
         * On TV remotes, increments the television channel. */
        AKEYCODE_CHANNEL_UP = 166,
        /** Channel down key.
         * On TV remotes, decrements the television channel. */
        AKEYCODE_CHANNEL_DOWN = 167,
        /** Zoom in key. */
        AKEYCODE_ZOOM_IN = 168,
        /** Zoom out key. */
        AKEYCODE_ZOOM_OUT = 169,
        /** TV key.
         * On TV remotes, switches to viewing live TV. */
        AKEYCODE_TV = 170,
        /** Window key.
         * On TV remotes, toggles picture-in-picture mode or other windowing functions. */
        AKEYCODE_WINDOW = 171,
        /** Guide key.
         * On TV remotes, shows a programming guide. */
        AKEYCODE_GUIDE = 172,
        /** DVR key.
         * On some TV remotes, switches to a DVR mode for recorded shows. */
        AKEYCODE_DVR = 173,
        /** Bookmark key.
         * On some TV remotes, bookmarks content or web pages. */
        AKEYCODE_BOOKMARK = 174,
        /** Toggle captions key.
         * Switches the mode for closed-captioning text, for example during television shows. */
        AKEYCODE_CAPTIONS = 175,
        /** Settings key.
         * Starts the system settings activity. */
        AKEYCODE_SETTINGS = 176,
        /** TV power key.
         * On TV remotes, toggles the power on a television screen. */
        AKEYCODE_TV_POWER = 177,
        /** TV input key.
         * On TV remotes, switches the input on a television screen. */
        AKEYCODE_TV_INPUT = 178,
        /** Set-top-box power key.
         * On TV remotes, toggles the power on an external Set-top-box. */
        AKEYCODE_STB_POWER = 179,
        /** Set-top-box input key.
         * On TV remotes, switches the input mode on an external Set-top-box. */
        AKEYCODE_STB_INPUT = 180,
        /** A/V Receiver power key.
         * On TV remotes, toggles the power on an external A/V Receiver. */
        AKEYCODE_AVR_POWER = 181,
        /** A/V Receiver input key.
         * On TV remotes, switches the input mode on an external A/V Receiver. */
        AKEYCODE_AVR_INPUT = 182,
        /** Red "programmable" key.
         * On TV remotes, acts as a contextual/programmable key. */
        AKEYCODE_PROG_RED = 183,
        /** Green "programmable" key.
         * On TV remotes, actsas a contextual/programmable key. */
        AKEYCODE_PROG_GREEN = 184,
        /** Yellow "programmable" key.
         * On TV remotes, acts as a contextual/programmable key. */
        AKEYCODE_PROG_YELLOW = 185,
        /** Blue "programmable" key.
         * On TV remotes, acts as a contextual/programmable key. */
        AKEYCODE_PROG_BLUE = 186,
        /** App switch key.
         * Should bring up the application switcher dialog. */
        AKEYCODE_APP_SWITCH = 187,
        /** Generic Game Pad Button #1.*/
        AKEYCODE_BUTTON_1 = 188,
        /** Generic Game Pad Button #2.*/
        AKEYCODE_BUTTON_2 = 189,
        /** Generic Game Pad Button #3.*/
        AKEYCODE_BUTTON_3 = 190,
        /** Generic Game Pad Button #4.*/
        AKEYCODE_BUTTON_4 = 191,
        /** Generic Game Pad Button #5.*/
        AKEYCODE_BUTTON_5 = 192,
        /** Generic Game Pad Button #6.*/
        AKEYCODE_BUTTON_6 = 193,
        /** Generic Game Pad Button #7.*/
        AKEYCODE_BUTTON_7 = 194,
        /** Generic Game Pad Button #8.*/
        AKEYCODE_BUTTON_8 = 195,
        /** Generic Game Pad Button #9.*/
        AKEYCODE_BUTTON_9 = 196,
        /** Generic Game Pad Button #10.*/
        AKEYCODE_BUTTON_10 = 197,
        /** Generic Game Pad Button #11.*/
        AKEYCODE_BUTTON_11 = 198,
        /** Generic Game Pad Button #12.*/
        AKEYCODE_BUTTON_12 = 199,
        /** Generic Game Pad Button #13.*/
        AKEYCODE_BUTTON_13 = 200,
        /** Generic Game Pad Button #14.*/
        AKEYCODE_BUTTON_14 = 201,
        /** Generic Game Pad Button #15.*/
        AKEYCODE_BUTTON_15 = 202,
        /** Generic Game Pad Button #16.*/
        AKEYCODE_BUTTON_16 = 203,
        /** Language Switch key.
         * Toggles the current input language such as switching between English and Japanese on
         * a QWERTY keyboard.  On some devices, the same function may be performed by
         * pressing Shift+Spacebar. */
        AKEYCODE_LANGUAGE_SWITCH = 204,
        /** Manner Mode key.
         * Toggles silent or vibrate mode on and off to make the device behave more politely
         * in certain settings such as on a crowded train.  On some devices, the key may only
         * operate when long-pressed. */
        AKEYCODE_MANNER_MODE = 205,
        /** 3D Mode key.
         * Toggles the display between 2D and 3D mode. */
        AKEYCODE_3D_MODE = 206,
        /** Contacts special function key.
         * Used to launch an address book application. */
        AKEYCODE_CONTACTS = 207,
        /** Calendar special function key.
         * Used to launch a calendar application. */
        AKEYCODE_CALENDAR = 208,
        /** Music special function key.
         * Used to launch a music player application. */
        AKEYCODE_MUSIC = 209,
        /** Calculator special function key.
         * Used to launch a calculator application. */
        AKEYCODE_CALCULATOR = 210,
        /** Japanese full-width / half-width key. */
        AKEYCODE_ZENKAKU_HANKAKU = 211,
        /** Japanese alphanumeric key. */
        AKEYCODE_EISU = 212,
        /** Japanese non-conversion key. */
        AKEYCODE_MUHENKAN = 213,
        /** Japanese conversion key. */
        AKEYCODE_HENKAN = 214,
        /** Japanese katakana / hiragana key. */
        AKEYCODE_KATAKANA_HIRAGANA = 215,
        /** Japanese Yen key. */
        AKEYCODE_YEN = 216,
        /** Japanese Ro key. */
        AKEYCODE_RO = 217,
        /** Japanese kana key. */
        AKEYCODE_KANA = 218,
        /** Assist key.
         * Launches the global assist activity.  Not delivered to applications. */
        AKEYCODE_ASSIST = 219,
        /** Brightness Down key.
         * Adjusts the screen brightness down. */
        AKEYCODE_BRIGHTNESS_DOWN = 220,
        /** Brightness Up key.
         * Adjusts the screen brightness up. */
        AKEYCODE_BRIGHTNESS_UP = 221,
        /** Audio Track key.
         * Switches the audio tracks. */
        AKEYCODE_MEDIA_AUDIO_TRACK = 222,
        /** Sleep key.
         * Puts the device to sleep.  Behaves somewhat like {@link AKEYCODE_POWER} but it
         * has no effect if the device is already asleep. */
        AKEYCODE_SLEEP = 223,
        /** Wakeup key.
         * Wakes up the device.  Behaves somewhat like {@link AKEYCODE_POWER} but it
         * has no effect if the device is already awake. */
        AKEYCODE_WAKEUP = 224,
        /** Pairing key.
         * Initiates peripheral pairing mode. Useful for pairing remote control
         * devices or game controllers, especially if no other input mode is
         * available. */
        AKEYCODE_PAIRING = 225,
        /** Media Top Menu key.
         * Goes to the top of media menu. */
        AKEYCODE_MEDIA_TOP_MENU = 226,
        /** '11' key. */
        AKEYCODE_11 = 227,
        /** '12' key. */
        AKEYCODE_12 = 228,
        /** Last Channel key.
         * Goes to the last viewed channel. */
        AKEYCODE_LAST_CHANNEL = 229,
        /** TV data service key.
         * Displays data services like weather, sports. */
        AKEYCODE_TV_DATA_SERVICE = 230,
        /** Voice Assist key.
         * Launches the global voice assist activity. Not delivered to applications. */
        AKEYCODE_VOICE_ASSIST = 231,
        /** Radio key.
         * Toggles TV service / Radio service. */
        AKEYCODE_TV_RADIO_SERVICE = 232,
        /** Teletext key.
         * Displays Teletext service. */
        AKEYCODE_TV_TELETEXT = 233,
        /** Number entry key.
         * Initiates to enter multi-digit channel nubmber when each digit key is assigned
         * for selecting separate channel. Corresponds to Number Entry Mode (0x1D) of CEC
         * User Control Code. */
        AKEYCODE_TV_NUMBER_ENTRY = 234,
        /** Analog Terrestrial key.
         * Switches to analog terrestrial broadcast service. */
        AKEYCODE_TV_TERRESTRIAL_ANALOG = 235,
        /** Digital Terrestrial key.
         * Switches to digital terrestrial broadcast service. */
        AKEYCODE_TV_TERRESTRIAL_DIGITAL = 236,
        /** Satellite key.
         * Switches to digital satellite broadcast service. */
        AKEYCODE_TV_SATELLITE = 237,
        /** BS key.
         * Switches to BS digital satellite broadcasting service available in Japan. */
        AKEYCODE_TV_SATELLITE_BS = 238,
        /** CS key.
         * Switches to CS digital satellite broadcasting service available in Japan. */
        AKEYCODE_TV_SATELLITE_CS = 239,
        /** BS/CS key.
         * Toggles between BS and CS digital satellite services. */
        AKEYCODE_TV_SATELLITE_SERVICE = 240,
        /** Toggle Network key.
         * Toggles selecting broadcast services. */
        AKEYCODE_TV_NETWORK = 241,
        /** Antenna/Cable key.
         * Toggles broadcast input source between antenna and cable. */
        AKEYCODE_TV_ANTENNA_CABLE = 242,
        /** HDMI #1 key.
         * Switches to HDMI input #1. */
        AKEYCODE_TV_INPUT_HDMI_1 = 243,
        /** HDMI #2 key.
         * Switches to HDMI input #2. */
        AKEYCODE_TV_INPUT_HDMI_2 = 244,
        /** HDMI #3 key.
         * Switches to HDMI input #3. */
        AKEYCODE_TV_INPUT_HDMI_3 = 245,
        /** HDMI #4 key.
         * Switches to HDMI input #4. */
        AKEYCODE_TV_INPUT_HDMI_4 = 246,
        /** Composite #1 key.
         * Switches to composite video input #1. */
        AKEYCODE_TV_INPUT_COMPOSITE_1 = 247,
        /** Composite #2 key.
         * Switches to composite video input #2. */
        AKEYCODE_TV_INPUT_COMPOSITE_2 = 248,
        /** Component #1 key.
         * Switches to component video input #1. */
        AKEYCODE_TV_INPUT_COMPONENT_1 = 249,
        /** Component #2 key.
         * Switches to component video input #2. */
        AKEYCODE_TV_INPUT_COMPONENT_2 = 250,
        /** VGA #1 key.
         * Switches to VGA (analog RGB) input #1. */
        AKEYCODE_TV_INPUT_VGA_1 = 251,
        /** Audio description key.
         * Toggles audio description off / on. */
        AKEYCODE_TV_AUDIO_DESCRIPTION = 252,
        /** Audio description mixing volume up key.
         * Louden audio description volume as compared with normal audio volume. */
        AKEYCODE_TV_AUDIO_DESCRIPTION_MIX_UP = 253,
        /** Audio description mixing volume down key.
         * Lessen audio description volume as compared with normal audio volume. */
        AKEYCODE_TV_AUDIO_DESCRIPTION_MIX_DOWN = 254,
        /** Zoom mode key.
         * Changes Zoom mode (Normal, Full, Zoom, Wide-zoom, etc.) */
        AKEYCODE_TV_ZOOM_MODE = 255,
        /** Contents menu key.
         * Goes to the title list. Corresponds to Contents Menu (0x0B) of CEC User Control
         * Code */
        AKEYCODE_TV_CONTENTS_MENU = 256,
        /** Media context menu key.
         * Goes to the context menu of media contents. Corresponds to Media Context-sensitive
         * Menu (0x11) of CEC User Control Code. */
        AKEYCODE_TV_MEDIA_CONTEXT_MENU = 257,
        /** Timer programming key.
         * Goes to the timer recording menu. Corresponds to Timer Programming (0x54) of
         * CEC User Control Code. */
        AKEYCODE_TV_TIMER_PROGRAMMING = 258,
        /** Help key. */
        AKEYCODE_HELP = 259,
        AKEYCODE_NAVIGATE_PREVIOUS = 260,
        AKEYCODE_NAVIGATE_NEXT = 261,
        AKEYCODE_NAVIGATE_IN = 262,
        AKEYCODE_NAVIGATE_OUT = 263,
        /** Primary stem key for Wear
         * Main power/reset button on watch. */
        AKEYCODE_STEM_PRIMARY = 264,
        /** Generic stem key 1 for Wear */
        AKEYCODE_STEM_1 = 265,
        /** Generic stem key 2 for Wear */
        AKEYCODE_STEM_2 = 266,
        /** Generic stem key 3 for Wear */
        AKEYCODE_STEM_3 = 267,
        /** Directional Pad Up-Left */
        AKEYCODE_DPAD_UP_LEFT = 268,
        /** Directional Pad Down-Left */
        AKEYCODE_DPAD_DOWN_LEFT = 269,
        /** Directional Pad Up-Right */
        AKEYCODE_DPAD_UP_RIGHT = 270,
        /** Directional Pad Down-Right */
        AKEYCODE_DPAD_DOWN_RIGHT = 271,
        /** Skip forward media key */
        AKEYCODE_MEDIA_SKIP_FORWARD = 272,
        /** Skip backward media key */
        AKEYCODE_MEDIA_SKIP_BACKWARD = 273,
        /** Step forward media key.
         * Steps media forward one from at a time. */
        AKEYCODE_MEDIA_STEP_FORWARD = 274,
        /** Step backward media key.
         * Steps media backward one from at a time. */
        AKEYCODE_MEDIA_STEP_BACKWARD = 275,
        /** Put device to sleep unless a wakelock is held. */
        AKEYCODE_SOFT_SLEEP = 276,
        /** Cut key. */
        AKEYCODE_CUT = 277,
        /** Copy key. */
        AKEYCODE_COPY = 278,
        /** Paste key. */
        AKEYCODE_PASTE = 279,
        /** fingerprint navigation key, up. */
        AKEYCODE_SYSTEM_NAVIGATION_UP = 280,
        /** fingerprint navigation key, down. */
        AKEYCODE_SYSTEM_NAVIGATION_DOWN = 281,
        /** fingerprint navigation key, left. */
        AKEYCODE_SYSTEM_NAVIGATION_LEFT = 282,
        /** fingerprint navigation key, right. */
        AKEYCODE_SYSTEM_NAVIGATION_RIGHT = 283,
        /** all apps */
        AKEYCODE_ALL_APPS = 284
    };

    /**
     * Key event actions.
     */
    enum class android_keyevent_action {
        /** The key has been pressed down. */
        AKEY_EVENT_ACTION_DOWN = 0,

        /** The key has been released. */
        AKEY_EVENT_ACTION_UP = 1,

        /**
         * Multiple duplicate key events have occurred in a row, or a
         * complex string is being delivered.  The repeat_count property
         * of the key event contains the number of times the given key
         * code should be executed.
         */
        AKEY_EVENT_ACTION_MULTIPLE = 2
    };

    /**
     * Meta key / modifier state.
     */
    enum class android_metastate : std::uint32_t {
        /** No meta keys are pressed. */
        AMETA_NONE = 0,

        /** This mask is used to check whether one of the ALT meta keys is pressed. */
        AMETA_ALT_ON = 0x02,

        /** This mask is used to check whether the left ALT meta key is pressed. */
        AMETA_ALT_LEFT_ON = 0x10,

        /** This mask is used to check whether the right ALT meta key is pressed. */
        AMETA_ALT_RIGHT_ON = 0x20,

        /** This mask is used to check whether one of the SHIFT meta keys is pressed. */
        AMETA_SHIFT_ON = 0x01,

        /** This mask is used to check whether the left SHIFT meta key is pressed. */
        AMETA_SHIFT_LEFT_ON = 0x40,

        /** This mask is used to check whether the right SHIFT meta key is pressed. */
        AMETA_SHIFT_RIGHT_ON = 0x80,

        /** This mask is used to check whether the SYM meta key is pressed. */
        AMETA_SYM_ON = 0x04,

        /** This mask is used to check whether the FUNCTION meta key is pressed. */
        AMETA_FUNCTION_ON = 0x08,

        /** This mask is used to check whether one of the CTRL meta keys is pressed. */
        AMETA_CTRL_ON = 0x1000,

        /** This mask is used to check whether the left CTRL meta key is pressed. */
        AMETA_CTRL_LEFT_ON = 0x2000,

        /** This mask is used to check whether the right CTRL meta key is pressed. */
        AMETA_CTRL_RIGHT_ON = 0x4000,

        /** This mask is used to check whether one of the META meta keys is pressed. */
        AMETA_META_ON = 0x10000,

        /** This mask is used to check whether the left META meta key is pressed. */
        AMETA_META_LEFT_ON = 0x20000,

        /** This mask is used to check whether the right META meta key is pressed. */
        AMETA_META_RIGHT_ON = 0x40000,

        /** This mask is used to check whether the CAPS LOCK meta key is on. */
        AMETA_CAPS_LOCK_ON = 0x100000,

        /** This mask is used to check whether the NUM LOCK meta key is on. */
        AMETA_NUM_LOCK_ON = 0x200000,

        /** This mask is used to check whether the SCROLL LOCK meta key is on. */
        AMETA_SCROLL_LOCK_ON = 0x400000,
    };

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
        std::optional<abs_enum_t<android_keyevent_action> > action;
    };

    class inject_keycode_msg final : public control_msg {
    public:
        [[nodiscard]] auto buf_size() const -> std::size_t override;

        auto serialize() -> std::vector<std::byte> override;

        std::optional<abs_enum_t<control_msg_type> > msg_type = abs_enum_t{
            control_msg_type::SC_CONTROL_MSG_TYPE_INJECT_KEYCODE
        };
        std::optional<abs_enum_t<android_keyevent_action> > action;
        std::optional<abs_enum_t<android_keycode, std::uint32_t> > keycode;
        std::optional<abs_int_t<std::uint32_t> > repeat;
        std::optional<abs_enum_t<android_metastate, std::uint32_t> > metastate;
    };
}


#endif //CONTROL_MSG_HPP
