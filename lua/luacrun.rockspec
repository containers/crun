--[[ This file is part of crun. SPDX: GPL-2.0-or-later

Please don't use this rockspec to make source rocks.
The generated rocks does not include files for a success build.
Use `make dist-luarock` instead.
]]
rockspec_format = "3.0"
package = "luacrun"
version = "@CLEANVERSION"
source = {
    url = "https://github.com/containers/crun/releases/download/@RELEASEVERSION/crun-@RELEASEVERSION.tar.gz",
}
supported_platforms = {'linux'}
description = {
    summary = "A Lua binding for libcrun, a fast and lightweight fully featured OCI runtime and C library for running containers.",
    detailed = [[
       libcrun is a fast and low-memory footprint OCI container runtime.
       This library bundles the binding for libcrun and a working libcrun.
    ]],
    homepage = "http://github.com/containers/crun/",
    license = "GPL-2.0-or-later"
}
dependencies = {"lua >= 5.4"}
build = {
    type = "command",
    build_command = [[
        rm -rf libocispec/yajl/src/api && ln -s ./headers/yajl libocispec/yajl/src/api &&
        ./configure --prefix=$(PREFIX) --libdir=$(LIBDIR) --disable-crun --disable-libcrun --enable-shared --with-lua-bindings --enable-embedded-yajl LUA=$(LUA) LUA_INCLUDE=-I$(LUA_INCDIR) &&
        make -j]],
    install_command = "make install",
}
