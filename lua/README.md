# Lua binding for libcrun

Bare libcrun interface for Lua.

There are some problems still and the API is a subject to change.

## Build

Only build static archive, to be bundled with another program:

````sh
./configure --with-lua-bindings
make && make install
````

Since the final product bundle libcrun, you don't need to link libcrun at runtime.


For the library using at runtime, add option `--enable-shared`:
````sh
./configure --with-lua-bindings --enable-shared
make && make install
````

Other options to build libcrun may affect the bundled libcrun.

## Usage

See `luacrun.d.tl`.

## Works with your LuaRocks project

You can build rocks (in luarocks) if lua bindings is enabled.

````sh
./configure --with-lua-bindings
make dist-luarock
````

The options here for `./configure` won't affect the final output, see `luacrun.rockspec` for the building options.

`dist-luarock` target packs a source rock. You can use `luarocks build luacrun-xxx.src.rock --pack-binary-rock` to pack binary rocks.

````sh
# Assume the filename is luacrun-1.8.4-0.src.rock
luarocks build luacrun-1.8.4-0.src.rock --pack-binary-rock
````

Another way is, configure the prefix to your `lua_modules` to access this library in your project.

````sh
./configure --with-lua-bindings --enable-shared --prefix $(pwd)/lua_modules
make && make install
````

## Interpreter may restart?

Related issue: [#695: [Python bindings] Python interpreter restarts (?) after first import of python_crun](https://github.com/containers/crun/issues/695)

The lua interpreter may restart at the first open of the library (may not happen if statically linked into your program). It's side effect of [a protection (click for the code)](https://github.com/containers/crun/blob/923447b691dbd7c5bffbaee1427460d62d848047/src/libcrun/linux.c#L3881-L3891) to avoid attacks like [CVE-2019-5736](https://nvd.nist.gov/vuln/detail/CVE-2019-5736).

To ease the hurt, always place the `require` call at the start of your program:

````lua
-- entry point module for luabundler
require "luacrun"

return function(...) -- the entry point
    print("Hello World!")
end
````

It's not required to use the library at the moment. Since it is cached, the `require()` will not open the library again.

If the entry point is at the C-side, you may use the `luaL_requiref` to open the library instead of `require()` call in Lua code.
````c
#include <lua.h>
#include <lauxlib.h>

extern int luaopen_luacrun(lua_State *S);

int main(int argc, char *argv[]) {
    lua_State *S = luaL_newstate();
    // Open the library before any actual logic,
    // to make sure users will not notice the program have actually started twice
    luaL_requiref(S, "luacrun", &luaopen_luacrun, false);
    lua_pop(S, 1);
    // ...your code
}
````

The protection might cause another problem in REPL:
````
$ lua
Lua 5.4.4  Copyright (C) 1994-2022 Lua.org, PUC-Rio
> luacrun = require "luacrun"
Lua 5.4.4  Copyright (C) 1994-2022 Lua.org, PUC-Rio
> luacrun
nil
>
````

When you call `require "luacrun"` at the first time, the REPL restarted and the state have been reset.

The workaround is `require "luacrun"` again and you get the library this time. The protection will not apply again if it's already applied.
````
$ lua
Lua 5.4.4  Copyright (C) 1994-2022 Lua.org, PUC-Rio
> luacrun = require "luacrun"
Lua 5.4.4  Copyright (C) 1994-2022 Lua.org, PUC-Rio
> luacrun
nil
> luacrun = require "luacrun"
> luacrun
table: 0x561edad470d0
>
````

It's safe to use luacrun in multi-state usage, the program restarts only once.


## Test

You need [busted](https://lunarmodules.github.io/busted/) and below dependencies to run tests:

- [dkjson](https://luarocks.org/modules/dhkolf/dkjson)
- [luaposix](https://luaposix.github.io)

````sh
luarocks install busted dkjson luaposix
````

The tests assume environment variable `INIT` exists. It's the `init` program compiled in `tests`.

````sh
INIT=$(pwd)/tests/init lua_modules/bin/busted lua
````
