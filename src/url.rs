/*!
  RFC 3986 Compliant URL parsing

  This is a port of Go's Url library.
    -http://golang.org/src/pkg/net/url/url.go

  From http://en.wikipedia.org/wiki/URI_scheme#Examples:

   foo://username:password@example.com:8042/over/there/index.dtb?type=animal&name=narwhal#nose
   \_/   \_______________/ \_________/ \__/            \___/ \_/ \______________________/ \__/
    |           |               |       |                |    |            |                |
    |       userinfo         hostname  port              |    |          query          fragment
    |    \________________________________/\_____________|____|/ \__/        \__/
    |                    |                          |    |    |    |          |
    |                    |                          |    |    |    |          |
 scheme              authority                    path   |    |    interpretable as keys
  name   \_______________________________________________|____|/       \____/     \_____/
    |                         |                          |    |          |           |
    |                 hierarchical part                  |    |    interpretable as values
    |                                                    |    |
    |            path               interpretable as filename |
    |   ___________|____________                              |
   / \ /                        \                             |
   urn:example:animal:ferret:nose               interpretable as extension
 
                 path
          _________|________
  scheme /                  \
   name  userinfo  hostname       query
   _|__   ___|__   ____|____   _____|_____
  /    \ /      \ /         \ /           \
  mailto:username@example.com?subject=Topic


  TODO: Fix the stringly typed Err(message).
*/

use std::fmt;
use std::str;

/// Error codes for Url parsing.
pub enum ErrorCode {
    /// Invalid url escape.
    /// TODO: impl
    /// func (e EscapeError) Error() string {
    ///     return "invalid URL escape " + strconv.Quote(string(e))
    /// }
    EscapeError
}

/// Converts the enum error codes to human readable strings.
pub fn error_str(error: ErrorCode) -> &'static str {
    return match error {
        EscapeError => "Escape error.",
    }
}


impl fmt::Show for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        error_str(*self).fmt(f)
    }
}

/// Error reports an error and the operation and URL that caused it.
pub struct Error<'a> {
    op:  &'a str,
    url: &'a str,
    error_code: ErrorCode
}


impl<'a> Error<'a> {
    fn error(&'a self) -> String {
        return self.op.to_string()
            .append(" ")
            .append(self.url)
            .append(": ")
            .append(error_str(self.error_code));
    }
}

/// Encoding is used to determine if a reserved error can appear unescaped.
#[deriving(PartialEq)]
pub enum Encoding {
    /// Paths
    EncodePath,
    /// Passwords
    EncodeUserPassword,
    /// Query Components
    EncodeQueryComponent,
    /// Fragments
    EncodeFragment
}

/// Return true if specified character should be escaped when
/// appearing in a URL string, according to RFC 3986/
/// When 'all' is true the full range of reserved characters are matched.
/// TODO: Rewrite this function with b'0'... when the feature arrives.
pub fn should_escape(c: u8, mode: Encoding) -> bool {
    // Unreserved characters (alphanum)
    return match c {
        d if '0' as u8 <= d && d <= '9' as u8 ||
             'a' as u8 <= d && d <= 'z' as u8 ||
             'A' as u8 <= d && d <= 'Z' as u8  => false,

            d if bytes!("-_.~").contains(&d)   => false,

            d if bytes!("$&+,/:;=?@").contains(&d) => match mode {
                EncodePath           => c == '?' as u8,

                EncodeUserPassword   => c == '@' as u8 ||
                                        c == '/' as u8 ||
                                        c == ':' as u8,

                EncodeQueryComponent => true,

                EncodeFragment       => false
            },

            _                                    => true
    }
}

/// Checks if a u8 is a hex representable.
/// TODO: Rewrite this function with b'0'... when the feature arrives.
pub fn ishex(c: u8) -> bool {
    return match c {
        d if '0' as u8 <= d && d <= '9' as u8 => true,
        d if 'a' as u8 <= d && d <= 'f' as u8 => true,
        d if 'A' as u8 <= d && d <= 'F' as u8 => true,
        _                                     => false
    }
}

/// TODO: Rewrite this function with b'0'... when the feature arrives.
pub fn unhex(c: u8) -> u8 {
    return match c {
        d if '0' as u8 <= d && d <= '9' as u8 => c - '0' as u8,
        d if 'a' as u8 <= d && d <= 'f' as u8 => c - 'a' as u8 + 10,
        d if 'A' as u8 <= d && d <= 'F' as u8 => c - 'A' as u8 + 10,
        _                                     => 0
    }
}


/// unescapes a string, the mode specifics which section of the URL string
/// is being unescaped
/// TODO: Rewrite this function with b'0'... when the feature arrives.
/// TODO: Refactor this beast.
pub fn unescape(s: String, mode: Encoding) -> Result<String, String> {
    let mut n = 0;
    let mut has_plus = false;
    let mut i = 0;
    let s_slice = s.as_slice();
    let s_len = s_slice.len();

    // check that % is well formed, and count them
    while i < s_len {
        match s_slice[i] {
            // '%' as u8
            37 => {
                n += 1;
                if i + 2 >= s_len || !ishex(s_slice[i + 1]) || !ishex(s_slice[i + 2]) {
                    let output = match s_len {
                        q if q - i > 3 => s_slice.slice(i, i + 3),
                        _              => s_slice.slice(i, s_len)
                    };
                    return Err(error_str(EscapeError)
                               .to_string()
                               .append(" ")
                               .append(output));
                }
                i += 3;
            },

            // '+' as u8
            43 => {
                if mode == EncodeQueryComponent {
                    has_plus = true;
                }
                i += 1;
            },

            // fall through
            _  => {
                i += 1;
            }
        }
    }

    // if we don't have any % then return
    if n == 0 && !has_plus {
        return Ok(s_slice.to_string());
    }

    // unescaped string
    let mut o = Vec::with_capacity(s_len - 2 * n);

    i = 0;
    while i < s_len {
        match s_slice[i] {
            // '%' as u8
            37 => {
                o.push(unhex(s_slice[i + 1]) << 4 | unhex(s_slice[i + 2]));
                i += 3;
            },

            // '+' as u8
            43 => {
                if mode == EncodeQueryComponent {
                    o.push(' ' as u8);
                } else {
                    o.push('+' as u8);
                }
                i += 1;
            },

            //fall through
            _ => {
                o.push(s_slice[i]);
                i += 1
            }

        }
    }


    return Ok(str::from_utf8(o.as_slice()).unwrap().to_string());
}

/// query_unescape does the inverse transform of query_escape, converting
/// %AB into the byte 0xAB and '+' into ' ' (space). It returns an error if
/// any % is not followed by two hexadecimal digits.
pub fn query_unescape(s: String) -> Result<String, String> {
    unescape(s, EncodeQueryComponent)
}


/// String escaping
pub fn escape(s: String, mode: Encoding) -> String {
    let (mut space_count, mut hex_count) = (0, 0);

    let s_vec = s.into_bytes();
    let s_len = s_vec.len();

    for c in s_vec.iter() {
        if should_escape(*c, mode) {
            if *c == (' ' as u8) && mode == EncodeQueryComponent {
                space_count += 1;
            } else {
                hex_count += 1;
            }
        }
    }

    if space_count == 0 && hex_count == 0 {
        return str::from_utf8(s_vec.as_slice()).unwrap().to_string();
    }

    let hex_dec = bytes!("0123456789ABCDEF");

    let mut o = Vec::with_capacity(s_len + 2 * hex_count);

    for i in s_vec.iter() {
        match i {
            x if *x == ' ' as u8 && mode == EncodeQueryComponent => {
                o.push('+' as u8);
            },

            x if should_escape(*x, mode)                         => {
                o.push('%' as u8);
                o.push(*hex_dec
                       .get((i >> 4) as uint)
                       .unwrap());
                o.push(*hex_dec
                       .get((i & 15) as uint)
                       .unwrap());
            },

            _                                                    => {
                o.push(*i);
            }
        }
    }

    return str::from_utf8(o.as_slice()).unwrap().to_string();
}

/// query_escape escapes the string so it can
/// be safely places inside a URL query.
pub fn query_escape(s: String) -> String {
    escape(s, EncodeQueryComponent)
}

/// Encapsulation of username and password details for a URL.
/// An existing UserInfo is guaranteed to have a username set (possibly empty),
/// and optionally a password.
pub struct UserInfo {
    /// Username for the URL.
    username: String,
    /// Password for the URL.
    password: String,
    /// Since the password is option, we need to flag it.
    passwordset: bool
}


/// A URL represents a parsed URL (technically, a URI reference).
/// The general form represented is:
///
/// scheme://[userinfo@]host/path[?query][#fragment]
pub struct URL<'a> {
    /// protocol scheme.
    pub scheme:    String,
    /// Encoded opaque data.
    pub opaque:    String,
    /// Username and password information.
    pub user:      &'a UserInfo,
    /// Host identifier
    pub host:      String,
    /// Path on the host
    pub path_:     String,
    /// Encoded query values, dropping the '?'
    pub raw_query: String,
    /// Fragment for references, without '#'
    pub fragment:  String
}


#[cfg(test)]
mod tests {
    use super::{ishex, should_escape, EncodePath, EncodeUserPassword,
                EncodeQueryComponent, query_unescape, query_escape};

    #[test]
    fn test_ishhex() {
        let should_pass = bytes!("059adfADF");
        for i in should_pass.iter() {
            assert_eq!(ishex(*i), true);
        }

        let should_fail = bytes!("zq';ä");
        for i in should_fail.iter() {
            assert_eq!(ishex(*i), false);
        }
    }

    #[test]
    fn test_should_escape() {
        assert_eq!(should_escape('z' as u8, EncodePath),           false);
        assert_eq!(should_escape('-' as u8, EncodePath),           false);
        assert_eq!(should_escape('?' as u8, EncodePath),           true);
        assert_eq!(should_escape('?' as u8, EncodeUserPassword),   false);
        assert_eq!(should_escape('?' as u8, EncodeQueryComponent), true);
    }

    struct EscapeTest {
        inp: String,
        out: Result<String, String>
    }

    #[test]
    fn test_query_unescape() {
        let tests: &[EscapeTest] = &[
            EscapeTest {
                inp: "".to_string(),
                out: Ok("".to_string())
            },
            EscapeTest {
                inp: "abc".to_string(),
                out: Ok("abc".to_string())
            },
            EscapeTest {
                inp: "1%41".to_string(),
                out: Ok("1A".to_string())
            },
            EscapeTest {
                inp: "1%41%42%43".to_string(),
                out: Ok("1ABC".to_string())
            },
            EscapeTest {
                inp: "%4a".to_string(),
                out: Ok("J".to_string())
            },
            EscapeTest {
                inp: "%6F".to_string(),
                out: Ok("o".to_string())
            },
            EscapeTest {
                inp: "%".to_string(),
                out: Err("Escape error. %".to_string())
            },
            EscapeTest {
                inp: "123%45%6".to_string(),
                out: Err("Escape error. %6".to_string())
            },
            EscapeTest {
                inp: "%zzzzz".to_string(),
                out: Err("Escape error. %zz".to_string())
            }
            ];

        for i in tests.iter() {
            let out = query_unescape(i.inp.clone());
            assert_eq!(out, i.out);

        }
    }

    #[test]
    fn test_query_escape() {
        let tests: &[EscapeTest] = &[
            EscapeTest {
                inp: "".to_string(),
                out: Ok("".to_string())
            },
            EscapeTest {
                inp: "abc".to_string(),
                out: Ok("abc".to_string())
            },
            EscapeTest {
                inp: "one two".to_string(),
                out: Ok("one+two".to_string())
            },
            EscapeTest {
                inp: "10%".to_string(),
                out: Ok("10%25".to_string())
            },
            EscapeTest {
                inp: " ?&=#+%!<>#\"{}|\\^[]`☺\t:/@$'()*,;".to_string(),
                out: Ok("+%3F%26%3D%23%2B%25%21%3C%3E%23%22%7B%7D%7C%5C%5E%5B%5D%60%E2%98%BA%09%3A%2F%40%24%27%28%29%2A%2C%3B".to_string())
            }];
        
        for i in tests.iter() {
            let out = query_escape(i.inp.clone());
            assert_eq!(Ok(out), i.out);
        }
    }
}
