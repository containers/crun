# Lua binding for libcrun

Bare libcrun interface for Lua.

There are some problems still and the API is a subject to change.

## LuaRocks build

To build luacrun luarocks package, you must have:

- Dependencies for building libcrun
- Lua 5.4 and its development files
- LuaRocks 3.x
- `sed`, `git` and `zip`

Started by `./configure`:

```
./autogen.sh && ./configure --with-lua-bindings
```

This is only to enable the option to build source rocks. The options to build the rocks is hard-coded at "lua/luacrun.rockspec".

Create the source rock:

```
make dist-luarock
```

You can find the new rock file as `luacrun-x.x.x-xx.src.rock`.

If you want the binary rock, use luarocks:
```
luarocks build <the-rock-file-name> --pack-binary-rock
```

## Regular build

Requirements:
- Dependencies for building libcrun
- Lua 5.4 and its development files

You can still build this module for regular directory structure, like:

```
./autogen.sh && ./configure --with-lua-bindings --disable-libcrun --disable-crun --enable-shared
```

The options here for `./configure` will affect the final output.

```
make && make install
```


## Usage

See `luacrun.d.tl`.

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

## Additional Build Options

- `--with-lua-bindings` enables the building options about the lua binding
- `--enable-lua-path-guessing`/`--disable-lua-path-guessing` enable or disable the lua module path guessing. If disabled, the install path for this module will be set to `libdir`.
