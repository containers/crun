--[[
Copyright (c) Rubicon Rowe

This file is part of crun. You can choose one of the following licenses for this file.

1. The MIT License
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

2. GNU Lesser General Public License v2.1 or later
crun is free software; you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation; either version 2.1 of the License, or
(at your option) any later version.

crun is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 NU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with crun.  If not, see <http://www.gnu.org/licenses/>.
]]

local record luacrun
    VERBOSITY_ERROR: integer
    VERBOSITY_WARNING: integer

    enum ContainerWorkState
        "stopped"
        "created"
        "paused"
        "running"
    end

    record Ctx userdata
        run: (function (ctx: Ctx, cont: Container, flags: ContainerRunFlags | nil): number | nil, string | nil)
        create: (function (ctx: Ctx, cont: Container, flags: ContainerRunFlags | nil): number | nil, string | nil)
        delete: (function (ctx: Ctx, id: string, force: boolean | nil): boolean, string | nil)
        kill: (function (ctx: Ctx, id: string, signame: string): boolean, string | nil)
        status: (function (ctx: Ctx, id: string): ContainerStat | nil, string | nil)
        start: (function (ctx: Ctx, id: string): boolean, string | nil)
        iter_names: (function (ctx: Ctx): any...)
        update: (function (ctx: Ctx, id: string, content: string): boolean, string | nil)

        -- Accessors
        -- All setters will return the old value.
        state_root: function(ctx: Ctx): string | nil
        set_state_root: function(ctx: Ctx, val: string | nil): string | nil
        id: function(ctx: Ctx): string | nil
        set_id: function(ctx: Ctx, val: string | nil): string | nil
        bundle: function(ctx: Ctx) : string | nil
        set_bundle: function(ctx: Ctx, val: string | nil): string | nil
        console_socket: function(ctx: Ctx): string | nil
        set_console_socket: function(ctx: Ctx, val: string | nil): string | nil
        pid_file: function(ctx: Ctx): string | nil
        set_pid_file: function(ctx: Ctx, val: string | nil): string | nil
        notify_socket: function(ctx: Ctx): string | nil
        set_notify_socket: function(ctx: Ctx, val: string | nil): string | nil
        handler: function(ctx: Ctx): string | nil
        set_handler: function(ctx: Ctx, val: string | nil): string | nil
        systemd_cgroup: function(ctx: Ctx): boolean
        set_systemd_cgroup: function(ctx: Ctx, val: boolean): boolean
    end

    record Container userdata
    end

    record ContainerStat
        ociVersion: string
        id: string
        pid: integer
        status: ContainerWorkState
        bundle: string
        rootfs: string
        ["systemd-scope"]: string | nil
        owner: string | nil
        annotations: {string: string} | nil
    end

    record ContainerRunFlags
        prefork: boolean | nil
    end

    record CtxOpts
        state_root: string | nil
        id: string | nil
        bundle: string | nil
        console_socket: string | nil
        pid_file: string | nil
        notify_socket: string | nil
        handler: string | nil
        systemd_cgroup: boolean | nil
        detach: boolean | nil
        args: {string}
    end

    new_ctx: (function (
        opts: CtxOpts
    ): Ctx)

    container_spec: (function (rootless: boolean | nil): string)

    -- New container object from spec string or spec file.
    -- These functions does not create container in context (and in environment),
    -- just make a new object for the spec.
    new_container_from_string: (function (json_string: string): Container)
    new_container_from_file: (function (file_path: string): Container)

    get_verbosity: (function (): integer)
    set_verbosity: (function (new_verbosity: integer): nil)

    -- Run a container in a context.
    -- Return 1 if success; `nil` and the error message if failed.
    run: (function (ctx: Ctx, cont: Container, flags: ContainerRunFlags | nil): number | nil, string | nil)

    -- Create the container described by `cont`.
    -- Return number (>= 0) if success; `nil` and the error message if failed
    create_container: (function (ctx: Ctx, cont: Container, flags: ContainerRunFlags | nil): number | nil, string | nil)

    -- Delete the container `id`.
    -- Return `true` if success; `false` and the error message if failed.
    delete_container: (function (ctx: Ctx, id: string, force: boolean | nil): boolean, string | nil)

    -- Kill the container `id` by signal `signame`.
    -- `signame` can be any name of supported Linux signals, or a string of the integer.
    -- If it's the name, it should be upper case (`"KILL"` not `"kill"`).
    -- Return `true` if success; `false` and the error message if failed.
    kill_container: (function (ctx: Ctx, id: string, signame: string): boolean, string | nil)

    -- Get the container status.
    -- Return a table if success; `nil` and the error message if failed.
    status_container: (function (ctx: Ctx, id: string): ContainerStat | nil, string | nil)

    -- Start the container.
    -- Return `true` if success; `false` and the error messgae if failed
    start_container: (function (ctx: Ctx, id: string): boolean, string | nil)

    -- Iterate all container names in `ctx`.
    -- Return iterator.
    iter_containers_names: (function (ctx: Ctx): any...)

    -- Update the container.
    -- Return `true` if success, `false` and the error message if failed.
    update_container: (function (ctx: Ctx, id: string, content: string): boolean, string | nil)
end


return luacrun
