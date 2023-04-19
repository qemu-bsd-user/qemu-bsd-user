--
-- SPDX-License-Identifier: BSD-2-Clause
--
-- Copyright (c) 2023 Warner Losh <imp@bsdimp.com>
--

-- Thanks to Kyle Evans for his makesyscall.lua in FreeBSD which served as
-- inspiration for this, and as a source of code at times.
--
-- SPDX-License-Identifier: BSD-2-Clause-FreeBSD
--
-- Copyright (c) 2019 Kyle Evans <kevans@FreeBSD.org>


-- We generally assume that this script will be run by flua, however we've
-- carefully crafted modules for it that mimic interfaces provided by modules
-- available in ports.  Currently, this script is compatible with lua from ports
-- along with the compatible luafilesystem and lua-posix modules.
local lfs = require("lfs")
local unistd = require("posix.unistd")

local FreeBSDSyscall = require("freebsd-syscall")	-- The FreeBSD specific syscall generator
local config = require("config")		-- Common config file mgt

-- Globals
local generated_tag = "@" .. "generated"

-- Default configuration; any of these may get replaced by a configuration file
-- optionally specified. A lot of these are passed into the fbsd_sys parser
-- and the bsd_user code generator
-- A bit tricky because a lot of the inherited code has a global config table that
-- it referrs to deep in the call tree... need to make sure that all that code is
-- converted to using one local to the object.
local config ={
}

-- Entry

if #arg < 1 or #arg > 2 then
	error("usage: " .. arg[0] .. " syscall.master")
end

local sysfile, configfile = arg[1], arg[2]

-- process_config either returns nil and a message, or a table that we should
-- merge into the global config. XXX Seems like this should be in config.something
if configfile ~= nil then
	local res = assert(config.process(configfile))

	for k, v in pairs(res) do
		if v ~= config[k] then
			config[k] = v
			config_modified[k] = true
		end
	end
end

-- The parsed syscall table
local tbl = FreeBSDSyscall:new(sysfile, config)
