# mono windows dotnet handler
* Make sure oci config contains handler for **mono** or image contains annotation **run.oci.handler=dotnet**.
* Entrypoint must point to a valid **.exe** (windows .NET compatible executable).
 ```json
...
"annotations": {
  "run.oci.handler": "dotnet"
},
...
```

## Examples
#### Compile and run `wasm` modules directly
* Following example is using `mono` to compile a cross platform executable but you can also use visual studio or any other build tools on windows.
* Add relevant function to `hello.cs` for this example we will be using a print.
 ```c#
  using System;
  using System.Runtime.CompilerServices;

  class MonoEmbed {
	static int Main ()
	{
		System.Console.WriteLine("hello");
		return 0;
	}
  }

```
* Compile a new `.exe` using `mcs -out:hello.exe hello.cs` if you have `mono` or you can `VisualStudio` or `dotnet build` as specified here: https://docs.microsoft.com/en-us/dotnet/core/tools/dotnet-build
* Create relevant image and use your container manager. But for this example we will be running directly using crun and plub config manually.
```console
$ crun run container-with-mono
hello
```

#### Running OCI `mono` compat images with buildah and podman
* Compile your `.exe` module using instructions from step one.
* Prepare a `Containerfile` with your `.exe`.
 ```Containerfile
 FROM scratch
COPY hello.exe /
CMD ["/hello.exe"]
 ```
* Build wasm image using buildah with annotation `run.oci.handler=dotnet`
```console
$ buildah build --annotation "run.oci.handler=dotnet" -t my-windows-executable .
```
* Make sure your podman points to oci runtime `crun` build with `mono` support.
* Run image using podman
```console
$ podman run --userns=keep-id my-windows-executable:latest
hello
```

#### Known-Issues
* Crun-mono containers needs user namespace for containers so with podman use `--userns=auto` or `--userns=keep-id`.
