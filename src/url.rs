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


*/

use std::fmt;

/// Error codes for Url parsing.
pub enum ErrorCode {
    /// Invalid url escape.
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

        d if d == '-' as u8 ||
             d == '_' as u8 ||
             d == '.' as u8 ||
             d == '~' as u8                    => false,

        d if bytes!("$&+,/:;=?@").contains(&d) => match mode {
            EncodePath           => c == '?' as u8,

            EncodeUserPassword   => c == '@' as u8 ||
                                    c == '/' as u8 ||
                                    c == ':' as u8,

            EncodeQueryComponent => true,

            EncodeFragment       => false
        },

        _                                      => true
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

/// lolwut
/// TODO: Rewrite this function with b'0'... when the feature arrives.
pub fn unhex(c: u8) -> u8 {
    return match c {
       d if '0' as u8 <= d && d <= '9' as u8 => c - '0' as u8,  
       d if 'a' as u8 <= d && d <= 'f' as u8 => c - 'a' as u8 + 10,
       d if 'A' as u8 <= d && d <= 'F' as u8 => c - 'A' as u8 + 10,
       _                                     => 0
    }
}

#[cfg(test)]
mod tests {
    use super::{ishex, should_escape, Encoding, EncodePath};

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
}
