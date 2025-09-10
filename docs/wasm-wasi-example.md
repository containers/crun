# crun-wasi-wasm example
* Make sure oci config contains handler for **wasm** or image contains annotation **module.wasm.image/variant=compat**.
* Entrypoint must point to a valid **.wat** (webassembly text) or **.wasm** (webassembly binary).
 ```json
...
"annotations": {
  "run.oci.handler": "wasm"
},
...
```


## Examples

#### Try out example with pre-built image and podman.

```console
podman run -it -p 8080:8080  --name=wasm-example  --platform=wasi/wasm32   michaelirwin244/wasm-example
```

#### Compiling and running `wasm` modules
* Following example is using `rust` to compile a webassembly module but you can use any supported language.
* Create a new rust binary using `cargo new hello_wasm --bin`.
* Add relevant function to `src/main.rs` for this example we will be using a print.
 ```rust
  fn main() {
   println!("{}", "This is from a main function from a wasm module");
  }
```
* Compile to `wasm32-wasip1` target using `wasm-pack` or any other relevant tool. We are going to be using `cargo build --target wasm32-wasip2`
* Create relevant image and use your container manager. But for this example we will be running directly using crun and plub config manually.
```console
$ crun run wasm-container
This is from a main function from a wasm module
```

#### Running OCI `wasm` compat images with buildah and podman
* Compile your `.wasm` module using instructions from step one.
* Prepare a `Containerfile` with your `.wasm` module.
 ```Containerfile
 FROM scratch
COPY hello.wasm /
ENTRYPOINT ["/hello.wasm"]
 ```
* Build wasm image using buildah
```console
$ buildah build --platform=wasi/wasm -t mywasm-image .
```
* Make sure your podman points to oci runtime `crun` build with `wasm` support.
* Run image using podman
```console
$ podman run mywasm-image:latest
This is from a main function from a wasm module
```
