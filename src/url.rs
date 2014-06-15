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


*/

use std::fmt;
use std::str;
use std::ascii::OwnedStrAsciiExt;

/// Error codes for URL parsing.
#[deriving(PartialEq)]
pub enum ParseError {
    /// Empty Url.
    EmptyUrl,
    /// Invalid Uri.
    InvalidUri,
    /// Hexadecimal escape in host.
    HexadecimalEscapeInHost,
    /// Escape error
    EscapeError,
    /// Missing protocol scheme
    MissingProtocolScheme
}

/// Converts the ParseError codes to human readable strings.
pub fn error_str(error: ParseError) -> &'static str {
    return match error {
        EmptyUrl                => "Empty url.",
        InvalidUri              => "Invalid uri.",
        HexadecimalEscapeInHost => "Hexadecimal escape in host.",
        EscapeError             => "Escape error.",
        MissingProtocolScheme   => "Missing protocol scheme."
    }
}


impl fmt::Show for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        error_str(*self).fmt(f)
    }
}

/*
/// Error reports an error and the operation and URL that caused it.
pub struct Error<'a> {
    op:  &'a str,
    url: &'a str,
    error_code: ParseError 
}
*/

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
pub fn unescape(s: String, mode: Encoding) -> Result<String, ParseError> {
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
                    return Err(EscapeError);
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
pub fn query_unescape(s: String) -> Result<String, ParseError> {
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
    password_set: bool
}


impl UserInfo {
    /// Returns a borrowed reference to the username.
    pub fn username<'a>(&'a self) -> &'a String {
        &self.username
    }
    
    /// If the password is set, it return a Some() that
    /// contains a borrowed reference to the password.
    pub fn password<'a>(&'a self) -> Option<&'a String> {
        if self.password_set {
            return Some(&self.password);
        }
        return None;
    }

    /// String returns the decoded UserInfo
    /// in the form "username[:password]"
    pub fn string(&self) -> String {
        let s = escape(self.username.clone(), EncodeUserPassword);
        if self.password_set {
            return s.append(escape(self.password.clone(), EncodeUserPassword).as_slice());
        } else {
            return s;
        }
    }
}


/// Returns a UserInfo containing the provided username
/// and no password set.
pub fn user(username: String) -> UserInfo {
    UserInfo {
        username: username,
        password: "".to_string(),
        password_set: false
    }
}


/// A URL represents a parsed URL (technically, a URI reference).
/// The general form represented is:
///
/// scheme://[userinfo@]host/path[?query][#fragment]
pub struct URL {
    /// protocol scheme.
    pub scheme:    String,
    /// Encoded opaque data.
    pub opaque:    String,
    /// Username and password information.
    pub user:      UserInfo,
    /// Host identifier
    pub host:      String,
    /// Path on the host
    pub path:      String,
    /// Encoded query values, dropping the '?'
    pub raw_query: String,
    /// Fragment for references, without '#'
    pub fragment:  String
}

fn empty_url() -> URL {
    return URL {
        scheme    : "".to_string(),
        opaque    : "".to_string(),
        user      : UserInfo {
            username     : "".to_string(),
            password     : "".to_string(),
            password_set : false
        },
        host      : "".to_string(),
        path      : "".to_string(),
        raw_query : "".to_string(),
        fragment  : "".to_string()
    }
}

/// If scheme is of the form scheme:path
/// Scheme must be [a-zA-Z]:[a-zA-Z0-9+-.]
/// If the schere is a scheme in this form, it will separate it
/// if not, it will put everything into path.
/// It fails if there's no protocol specified.
///
/// TODO: I really don't like this function.
/// It's tuply and the semantics are effed.
/// Option -> Result?
#[deprecated]
pub fn get_scheme(raw_url: String) -> Option<(String, String)> {
    let raw_bytes = raw_url.clone().into_bytes();
    let raw_len = raw_bytes.len();
    for i in range(0, raw_len) {
        let c = raw_bytes.get(i);
        match *c {
            c if 'a' as u8 <= c && c <= 'z' as u8 ||
                 'A' as u8 <= c && c <= 'Z' as u8 => {
                continue;
            }

            c if '0' as u8 <= c && c <= '9' as u8 ||
                 c == '+' as u8                   ||
                 c == '-' as u8                   ||
                 c == '.' as u8                   => {
                if i == 0 {
                    return None;
                }
                return Some(("".to_string(), raw_url.clone()));
            }

            c if c == ':' as u8                   => {
                if i == 0 {
                    return None;
                }
                return Some((str::from_utf8(raw_bytes.slice(0, i)).unwrap().to_string(),
                             str::from_utf8(raw_bytes.slice(i+1, raw_len)).unwrap().to_string()));
            }
            _                                     => {
                return Some(("".to_string(), raw_url));
            }
        }
    }
    return Some(("".to_string(), raw_url.clone()));
}

/// If s @ t:c:u has the substring c and cutc == false,
///     return (t, c u)
/// If cutc == true,
///     return (t, u)
/// If s does not has the substring c
///     return (s, "")
fn split(s: String, c: String, cutc: bool) -> (String, String) {
    let s_slice = s.as_slice();
    let res = s_slice.find_str(c.as_slice());
    match res {
        Some(x) => {
            if cutc {
                return (s_slice.slice(0, x).to_str(),
                        s_slice.slice(x + c.len(), s.len()).to_str());
            } else {
                return (s_slice.slice(0, x).to_str(),
                        s_slice.slice(x, s.len()).to_str());
            }
        },
        None    => {
            return (s.to_string(), "".to_string());
        }
    };
}


/// TODO: Rewrite this function with b'0'... when the feature arrives.
fn getscheme(rawurl: String) -> Result<(String, String), ParseError> {
    let r_clone = rawurl.clone();
    let bytes = r_clone.as_slice();
    let b_len = bytes.len();
    for i in range(0, b_len) {
        match bytes[i] {

            x if 'a' as u8 <= x && x <= 'z' as u8 ||
                 'A' as u8 <= x && x <= 'Z' as u8 => {
                     continue;
                 },

            x if '0' as u8 <= x && x <= '9' as u8 ||
                 x == '+' as u8                   ||
                 x == '-' as u8                   ||
                 x == '.' as u8                   => {
                     if i == 0 {
                        return Ok(("".to_string(), rawurl));
                     }
                 },

            x if x == ':' as u8 => {
                if i == 0 {
                    return Err(MissingProtocolScheme);
                } else {
                    return Ok((bytes.slice(0, i).to_str(), bytes.slice(i + 1, b_len).to_str()));
                }
            },

            _ => {
                return Ok(("".to_string(), rawurl));
            }
        }
    }
    return Ok(("".to_string(), rawurl));
}

/// parse parses a URL from a string in one of two contexts.  If
/// viaRequest is true, the URL is assumed to have arrived via an HTTP request,
/// in which case only absolute URLs or path-absolute relative URLs are allowed.
/// If viaRequest is false, all forms of relative URLs are allowed.
fn parse(rawurl: String, via_request: bool) -> Result<URL, ParseError> {
    
    if rawurl == "".to_string() && via_request {
        return Err(EmptyUrl);
    }

    let mut out = empty_url();

    if rawurl == "*".to_string() {
        out.path = "*".to_string();
        return Ok(out);
    }

    let scheme = getscheme(rawurl.clone());

    if scheme.is_err() {
        match scheme {
            Err(x) => {
                return Err(x);
            }
            _      => {
                fail!("This is a bug, please contact the author.");
            }
        }
    }

    let x = scheme.unwrap();

    out.scheme = x.clone().val0().into_ascii_lower();
    let mut rest = x.val1();

    let rem = split(rest, "?".to_string(), true);
    
    rest = rem.clone().val0();
    out.raw_query = rem.val1();

    let raw_c = rawurl.clone();
    let raw_slice = raw_c.as_slice();
    if raw_slice[0] != '/' as u8 {
        if out.scheme != "".to_string() {
            // Rootless paths are considered opaque according to RFC 3986
            out.opaque = rest;
            return Ok(out)
        }

        if via_request {
            return Err(InvalidUri)
        }
    }

    if out.scheme != "".to_string() || !via_request && (raw_slice.slice(0,3).as_bytes() != bytes!("///")) {
        if raw_slice.slice(0,2).as_bytes() == bytes!("//") {
            let (authority, rest) = split(rest.as_slice().slice(2,rest.len()).to_str(), "/".to_string(), false);
        }
    }

    return Ok(out);
    
}
/*
fn parse_authority(authority: String) -> Result<(UserInfo, string), ParseError> {

}
*/


/// Parse parses rawurl into a URL structure
/// The rawurl may be relative or absolute
///pub fn Parse(rawurl: String) -> (&URL, Error) {
///    let (u, frag) = split(rawurl, "#".to_string(), true);
///}


#[cfg(test)]
mod tests {
    use super::{ishex, should_escape, EncodePath, EncodeUserPassword,
                EncodeQueryComponent, query_unescape, query_escape,
                ParseError, EscapeError};

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
        out: Result<String, ParseError>
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
                out: Err(EscapeError)
            },
            EscapeTest {
                inp: "123%45%6".to_string(),
                out: Err(EscapeError)
            },
            EscapeTest {
                inp: "%zzzzz".to_string(),
                out: Err(EscapeError)
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

            let escaped = query_escape(i.inp.clone());
            assert_eq!(Ok(escaped.clone()), i.out);

            // test that unescape(escape(x)) == x
            let unescaped = query_unescape(escaped).unwrap();
            if unescaped != i.inp {
                println!("{}: {}", unescaped, i.inp);
            }
            assert_eq!(unescaped, i.inp);
        }
    }
}
