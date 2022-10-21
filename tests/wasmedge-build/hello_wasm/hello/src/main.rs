use std::env;
fn main() {
    println!("Print env::args()");
    for arg in env::args() {
        println!("{arg}");
    }
    println!("Print env::vars()");
    // In this test, the `container=podman`
    match env::var("container") {
        Ok(val) => println!("container: {val:?}"),
        Err(e) => println!("couldn't interpret container: {e}"),
    }
    // In this test, the `key=value`
    match env::var("key") {
        Ok(val) => println!("key: {val:?}"),
        Err(e) => println!("couldn't interpret key: {e}"),
    }
    println!("{}", "This is from a main function from a wasm module");
}
