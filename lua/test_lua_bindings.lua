-- crun - OCI runtime written in C
--
-- Copyright (C) 2026 crun Authors
-- crun is free software; you can redistribute it and/or modify
-- it under the terms of the GNU Lesser General Public License as published by
-- the Free Software Foundation; either version 2.1 of the License, or
-- (at your option) any later version.
--
-- crun is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU Lesser General Public License for more details.
--
-- You should have received a copy of the GNU Lesser General Public License
-- along with crun.  If not, see <http://www.gnu.org/licenses/>.
--
-- Smoke test for the Lua bindings.  It does not run a container (that
-- requires a privileged environment); it only exercises the parts of the
-- module that must keep working so a build/link regression is caught early.
-- Set package.cpath (or LUA_CPATH) so that require("luacrun") resolves to
-- the freshly built luacrun.so before running.

local crun = require("luacrun")

-- Spec generation must keep working (feature exercised by callers).
local spec = crun.container_spec(true)
assert(type(spec) == "string" and #spec > 0, "generated spec is empty")
assert(spec:find("ociVersion"), "generated spec has no ociVersion")

-- Every documented entry point must be present.  This also catches a missing
-- registration in luacrun_library_reg.
local expected = {
  "new_ctx", "container_spec", "new_container_from_string",
  "new_container_from_file", "get_verbosity", "set_verbosity", "run",
  "create_container", "delete_container", "kill_container",
  "start_container", "status_container", "iter_container_names",
  "update_container",
}
for _, name in ipairs(expected) do
  assert(crun[name] ~= nil, "missing function " .. name)
end

-- Verbosity constants.
for _, name in ipairs({ "VERBOSITY_ERROR", "VERBOSITY_WARNING", "VERBOSITY_DEBUG" }) do
  assert(crun[name] ~= nil, "missing constant " .. name)
end

crun.set_verbosity(crun.VERBOSITY_ERROR)
assert(crun.get_verbosity() == crun.VERBOSITY_ERROR, "verbosity round-trip failed")

-- Loading a container from the generated spec must resolve every symbol the
-- module needs (this is what caught the missing parse_json_file /
-- libcrun_container_spec exports).
assert(crun.new_container_from_string(spec) ~= nil, "new_container_from_string failed")

print("lua bindings smoke test: OK")
