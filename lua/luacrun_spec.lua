local dkjson = require "dkjson"
local posix = require "posix"
local stdlib = require "posix.stdlib"
local unistd = require "posix.unistd"
local libgen = require "posix.libgen"

local function is_file_exists(path)
    local f = io.open(path, 'rb')
    if f then
        f:close()
        return true
    else
        return false
    end
end

local function makedirs(path)
    if not is_file_exists(path) then
        makedirs(libgen.dirname(path))
        local path, errmsg = posix.mkdir(path)
        assert(path, errmsg)
    end
end

local function cp(src, dest)
    local stat, exitm, retc = os.execute(
                                  string.format("cp \"%s\" \"%s\"", src, dest))
    return retc
end

local function mktestenv()
    local format = string.format
    local init_path = os.getenv("INIT")
    assert(type(init_path) == "string" and #init_path > 0, "no INIT env var for init program")
    local path, errmsg = stdlib.mkdtemp("/tmp/luacrun-test-XXXXXX")
    assert(path, errmsg)
    local rootfs_path = string.format("%s/%s", path, "rootfs")
    makedirs(rootfs_path)
    for i, p in ipairs({
        "usr/bin", "etc", "var", "lib", "lib64", "usr/share/zoneinfo/Europe",
        "proc", "sys", "dev"
    }) do makedirs(string.format("%s/%s", rootfs_path, p)) end
    local sbin_path = string.format("%s/%s", rootfs_path, "sbin")
    makedirs(sbin_path)

    local retc = cp(init_path, format("%s/%s", rootfs_path, "init"))
    assert(retc == 0, "cp init to rootfs return " .. retc)
    local retc = cp(init_path, format("%s/%s", sbin_path, "init"))
    assert(retc == 0, "cp init to sbin return " .. retc)

    unistd.link("../usr/share/zoneinfo/Europe/Rome",
                format("%s/%s", rootfs_path, "etc/localtime"))

    local passwd, errmsg = io.open(format("%s/%s", rootfs_path,
                                          "usr/share/passwd"), "w")
    assert(passwd, errmsg)
    passwd, errmsg = passwd:write("root:x:0:0:root:/root:/bin/bash\n")
    assert(passwd, errmsg)
    passwd:close()
    unistd.link("../usr/share/passwd",
                format("%s/%s", rootfs_path, "etc/passwd"))
    return path
end

insulate("luacrun", function()
    local luacrun = require "luacrun"

    describe("container_spec", function()
        it("returns a string", function()
            local s = luacrun.container_spec()
            assert.are.equals("string", type(s))
        end)

        it("returns a json object", function()
            local s = luacrun.container_spec()
            local t = dkjson.decode(s)
            assert.are.equals("table", type(t))
        end)
    end)

    describe("new_ctx", function()
        it("can create context with only id", function()
            local ctx = luacrun.new_ctx {id = "luacrun-test"}
            assert.are.equals("userdata", type(ctx))
        end)
    end)

    describe("new_container_from_string", function()
        it("can create container object from json string", function()
            local spec = dkjson.decode(luacrun.container_spec())
            spec.root.path = "/"
            spec.process.args = {'/bin/echo', "Hello World!"}
            local cont, err = luacrun.new_container_from_string(dkjson.encode(
                                                                    spec))
            assert(cont, err)
        end)
    end)

    describe("create_container", function()
        it("is same to ctx.create", function()
            local ctx = luacrun.new_ctx {id = "luacrun-test"}
            assert.are.equals(ctx.create, luacrun.create_container)
        end)
    end)

    it("can create container and delete container", function()
        local temproot = mktestenv()
        local ctx = luacrun.new_ctx {state_root = temproot, id = "luacrun-test"}
        assert(ctx)
        local spec =
            dkjson.decode(luacrun.container_spec(unistd.geteuid() == 0))
        spec.root = {
            path = string.format("%s/%s", temproot, "rootfs"),
            readonly = true
        }
        spec.process.args = {'/init', "true"}
        spec.process.terminal = false
        spec.process.user = {uid = unistd.geteuid(), gid = unistd.getegid()}
        spec.linux.rootfsPropagation = "rprivate"
        local json_spec = dkjson.encode(spec)
        local cont, err = luacrun.new_container_from_string(json_spec)
        assert(cont, err)
        local stat, err = luacrun.create_container(ctx, cont)
        assert(stat == 0, string.format("%s, %d", err, stat))
        local names = {}
        for i, name in ctx:iter_names() do names[#names + 1] = name end
        assert(#names == 1, string.format("names length is %d", #names))
        local status, err = ctx:status(names[1])
        assert(status, err)
        assert.are.equals("created", status.status)
        local stat, err = ctx:start(names[1])
        assert(stat, err)
        local status, err = ctx:status(names[1])
        assert(status, err)
        assert.are.equals("running", status.status)
        while true do -- wait for container exited
            local status, err = ctx:status(names[1])
            assert(status, err)
            if status.status == "created" or status.status == "stopped" then
                break
            end
        end
        local stat, err = luacrun.delete_container(ctx, names[1])
        assert(stat, err)

        -- Make sure no container after deleted
        local names_after_deleted = {}
        for i, name in ctx:iter_names() do names_after_deleted[#names_after_deleted + 1] = name end
        assert(#names_after_deleted == 0, string.format("names length is %d", #names))
    end)

    describe("new_ctx()", function ()
        it("error if the argument has invalid type", function ()
            for i, v in ipairs({1, 1.0, false}) do
                assert.has_error((function ()
                    luacrun.new_ctx(v)
                end))
            end
        end)
    end)

    describe("Ctx", function()
        it("id() can get id", function()
            local ctx = luacrun.new_ctx {id = "luacrun-test"}
            assert.are.equals("luacrun-test", ctx:id())
        end)

        it("id() can read the id set by set_id()", function()
            local ctx = luacrun.new_ctx {id = "luacrun-test1"}
            assert.are.equals("luacrun-test1", ctx:id())
            ctx:set_id("luacrun-test2")
            assert.are.equals("luacrun-test2", ctx:id())
        end)

        it("systemd_cgroup() can get a boolean", function()
            local ctx = luacrun.new_ctx {id = "luacrun-test"}
            assert.are.equals("boolean", type(ctx:systemd_cgroup()))
        end)

        it("systemd_cgroup() can read the value set by set_system_cgroupd()",
           function()
            local ctx = luacrun.new_ctx {
                id = "luacrun-test",
                systemd_cgroup = false
            }
            assert.is_false(ctx:systemd_cgroup())
            ctx:set_systemd_cgroup(true)
            assert.is_true(ctx:systemd_cgroup())
        end)

        describe("iter_names()", function ()
            it("acts as empty iterator if no container", function ()
                local touch = false
                local ctx = luacrun.new_ctx {
                    id = "luacrun-test-empty",
                }

                for i, name in ctx:iter_names() do
                    touch = true
                end
                assert.is_false(touch)
            end)
        end)
    end)
end)
