# crun-wasi-wasm example
* Make sure oci config contains handler for **wasm**.
* Entrypoint must point to a valid **.wat** (webassembly text) or **.wasm** (webassembly binary).
 ```json
...
"annotations": {
  "run.oci.handler": "wasm"
},
...
```

### Example
* Following example is using `rust` to compile a webassembly module but you can use any supported language.
* Create a new rust binary using `cargo new hello_wasm --bin`.
* Add relevent function to `src/main.rs` for this example we will be using a print.
 ```rust
  fn main() {
   println!("{}", "This is from a main function from a wasm module");
  }
```
* Compile to `wasm32-wasi` target using `wasm-pack` or any other relevent tool. We are going to be using `cargo build --target wasm32-wasi`
* Create relevent image and use your container manager. But for this example we will be running directly using crun and plub config manually.
```console
$ crun run wasm-container
This is from a main function from a wasm module
```
