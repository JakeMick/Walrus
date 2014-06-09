extern crate walrus;
use walrus::url::query_unescape;

fn main() {
    let x = &"dicksdfjndfknjsdfks".to_string();
    let a = std::mem::size_of_val(&x);
	println!("{}", a);
}
