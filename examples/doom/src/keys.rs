pub const RIGHTARROW: u8 = 0xae;
pub const LEFTARROW: u8 = 0xac;
pub const UPARROW: u8 = 0xad;
pub const DOWNARROW: u8 = 0xaf;
pub const USE: u8 = 0xa2;
pub const FIRE: u8 = 0xa3;
pub const ESCAPE: u8 = 27;
pub const ENTER: u8 = 13;
pub const TAB: u8 = 9;
pub const F1: u8 = 0x80 + 0x3b;
pub const F2: u8 = 0x80 + 0x3c;
pub const F3: u8 = 0x80 + 0x3d;
pub const F4: u8 = 0x80 + 0x3e;
pub const F5: u8 = 0x80 + 0x3f;
pub const F6: u8 = 0x80 + 0x40;
pub const F7: u8 = 0x80 + 0x41;
pub const F8: u8 = 0x80 + 0x42;
pub const F9: u8 = 0x80 + 0x43;
pub const F10: u8 = 0x80 + 0x44;
pub const F11: u8 = 0x80 + 0x57;
pub const F12: u8 = 0x80 + 0x58;

pub const BACKSPACE: u8 = 0x7f;
pub const PAUSE: u8 = 0xff;

pub const EQUALS: u8 = 0x3d;
pub const MINUS: u8 = 0x2d;

pub const RSHIFT: u8 = 0x80 + 0x36;
pub const RCTRL: u8 = 0x80 + 0x1d;
pub const ALT: u8 = 0x80 + 0x38;

pub const CAPSLOCK: u8 = 0x80 + 0x3a;
pub const SCRLCK: u8 = 0x80 + 0x46;
pub const PRTSCR: u8 = 0x80 + 0x59;

pub const HOME: u8 = 0x80 + 0x47;
pub const END: u8 = 0x80 + 0x4f;
pub const PGUP: u8 = 0x80 + 0x49;
pub const PGDN: u8 = 0x80 + 0x51;
pub const INS: u8 = 0x80 + 0x52;
pub const DEL: u8 = 0x80 + 0x53;

pub fn from_sdl2(key: sdl2::keyboard::Keycode) -> Option<u8> {
    use sdl2::keyboard::Keycode as K;
    Some(match key {
        K::Right => RIGHTARROW,
        K::Left => LEFTARROW,
        K::Up => UPARROW,
        K::Down => DOWNARROW,
        K::Escape => ESCAPE,
        K::Return => ENTER,
        K::Tab => TAB,
        K::F1 => F1,
        K::F2 => F2,
        K::F3 => F3,
        K::F4 => F4,
        K::F5 => F5,
        K::F6 => F6,
        K::F7 => F7,
        K::F8 => F8,
        K::F9 => F9,
        K::F10 => F10,
        K::F11 => F11,
        K::F12 => F12,
        K::Backspace => BACKSPACE,
        K::Pause => PAUSE,
        K::Equals => EQUALS,
        K::Minus => MINUS,
        K::LShift | K::RShift => RSHIFT,
        K::RCtrl => RCTRL,
        K::LAlt | K::RAlt => ALT,
        K::CapsLock => CAPSLOCK,
        K::ScrollLock => SCRLCK,
        K::PrintScreen => PRTSCR,
        K::Home => HOME,
        K::End => END,
        K::PageUp => PGUP,
        K::PageDown => PGDN,
        K::Insert => INS,
        K::Delete => DEL,

        // QWERTY
        K::W => UPARROW,
        K::A => LEFTARROW,
        K::S => DOWNARROW,
        K::D => RIGHTARROW,

        // DVORAK
        K::Comma => UPARROW,
        K::O => DOWNARROW,
        K::E => RIGHTARROW,

        //=> STRAFE_R,
        K::Space => USE,
        K::LCtrl => FIRE,

        // K::A => b'a',
        K::B => b'b',
        K::C => b'c',
        // K::D => b'd',
        // K::E => b'e',
        K::F => b'f',
        K::G => b'g',
        K::H => b'h',
        K::I => b'i',
        K::J => b'j',
        K::K => b'k',
        K::L => b'l',
        K::M => b'm',
        K::N => b'n',
        // K::O => b'o',
        K::P => b'p',
        K::Q => b'q',
        K::R => b'r',
        // K::S => b's',
        K::T => b't',
        K::U => b'u',
        K::V => b'v',
        // K::W => b'w',
        K::X => b'x',
        K::Y => b'y',
        K::Z => b'z',
        K::Num0 => b'0',
        K::Num1 => b'1',
        K::Num2 => b'2',
        K::Num3 => b'3',
        K::Num4 => b'4',
        K::Num5 => b'5',
        K::Num6 => b'6',
        K::Num7 => b'7',
        K::Num8 => b'8',
        K::Num9 => b'9',

        K::Exclaim => b'!',
        K::Quotedbl => b'"',
        K::Hash => b'#',
        K::Dollar => b'$',
        K::Percent => b'%',
        K::Ampersand => b'&',
        K::Quote => b'\'',
        K::LeftParen => b'(',
        K::RightParen => b')',
        K::Asterisk => b'*',
        K::Plus => b'+',
        // K::Comma => b',',
        K::Period => b'.',
        K::Slash => b'/',
        K::Colon => b':',
        K::Semicolon => b';',
        K::Less => b'<',
        K::Greater => b'>',
        K::Question => b'?',
        K::At => b'@',
        K::LeftBracket => b'[',
        K::Backslash => b'\\',
        K::RightBracket => b']',
        K::Caret => b'^',
        K::Underscore => b'_',
        K::Backquote => b'`',

        K::KpDivide => b'/',
        K::KpMultiply => b'*',
        K::KpMinus => b'-',
        K::KpPlus => b'+',
        K::KpEnter => ENTER,
        K::KpPeriod => 0,
        K::KpEquals => EQUALS,

        K::Kp0 => 0,
        K::Kp1 => END,
        K::Kp2 => DOWNARROW,
        K::Kp3 => PGDN,
        K::Kp4 => LEFTARROW,
        K::Kp5 => b'5',
        K::Kp6 => RIGHTARROW,
        K::Kp7 => HOME,
        K::Kp8 => UPARROW,
        K::Kp9 => PGUP,

        _ => return None,
    })
}
