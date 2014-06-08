extern crate walrus;
use walrus::url::query_unescape;

fn main() {
    let a = query_unescape("%".to_string());
	println!("{}", a);
}
