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

local FreeBSDSyscall = require("freebsd-syscall")
						-- The FreeBSD syscall generator
local config = require("config")		-- Common config file mgt

-- Globals
local generated_tag = "@" .. "generated"

-- Default configuration; any of these may get replaced by a configuration file
-- optionally specified. A lot of these are passed into the fbsd_sys parser and
-- the bsd_user code generator A bit tricky because a lot of the inherited code
-- has a global config table that it referrs to deep in the call tree... need to
-- make sure that all that code is converted to using one local to the object.
local config ={
}

-- Entry

if #arg < 1 or #arg > 2 then
	error("usage: " .. arg[0] .. " syscall.master")
end

local sysfile, configfile = arg[1], arg[2]

-- process_config either returns nil and a message, or a table that we should
-- merge into the global config. XXX Seems like this should be in
-- config.something instead of bare code.
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

-- We need to generate several files
-- Generate prototypes for all the functions generated below
-- Generate a system call cable for all these functions
--    note: some changes may be needed to put args into an array
-- Generate the actual code for all these functions
-- Generate a table for strace to accurately report args, etc
--
-- We also need to document the conventions used
--    - how are things named
--        bsd_foo will be generated
--    - how do we opt-out for complex things
--        the config table will have a nogen table that tells
--        us which functions not to generate, but they will
--        still get prototypes generated, and the be in the
--        system call table
--
-- Also related, we'd need to create a number of functions for each of the data
-- types. We'll need to get this list from tbl, but then we'll need some way to
-- get the data structures (likely via an C file with a bunch of include files
-- that's run through cpp). Much of this can be generated, though there are
-- limits that may be poorly understood (especially knowing what needs to
-- be locked into memory and for how long).
--
-- t2h_foo	Convert a struct foo from the target to the host (with
--		host storage on the stack). This function locks and unlocks
--		the target memory while the g2h_foo function is called.
-- h2t_foo	Same but converting a host structure to a target one (with
--		the target storage referenced by
-- g2h_foo	Converts a guest's foo to a host's foo, assuming that the
--		guest's foo is already locked into memory.
-- h2g_foo	Same, but converts a host's foo to a guest's.
--
-- These functions will be assumed to exist in the generated 'actual code'.  It
-- is hoped that the _In* _Out* annotations will suffice to know what to leave
-- locked, what manual locking needs to happen etc. This dicotomy cam be seen in
-- today's code where we have LOCK_IOVEC and UNLOCK_IOVEC which bracket the
-- system calls, and something like target_to_host_rusage() which does the lock,
-- translates, then unlocks in one call. Also: strings or pointers with arrays
-- of results (though I think there's enough).
--
-- The prototypes to the above need to be generated. Unlike the current code,
-- I'd like to do them all as static inline functions (not sure if having macros
-- to help that is good, or if the expansion should just be done in this
-- program.
--
-- XXX Also, how do I know when to use safe_XXXX instead of a raw XXXX?
-- XXX Do I also need to generate all the safe_XXXX functions and just use
-- them always? Is that too much overhead?
--
-- So there's a lot of moving parts here. Also need to come up with the right
-- structure for it so we can start testing ASAP.
--
-- Also note for those that want $OTHERBSD support: this structure should
-- translate well to having a parser that parse the data and then a generator
-- that runs. However, both OpenBSD and NetBSD's syscalls.master files lack a
-- lot of the in/out data we need, so some alternative would need to be done.
