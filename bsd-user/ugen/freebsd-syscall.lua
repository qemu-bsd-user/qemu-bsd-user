--
-- SPDX-License-Identifier: BSD-2-Clause
--
-- Copyright (c) 2023 Warner Losh <imp@bsdimp.com>
--

-- Derived in large part from makesyscalls.lua:
--
-- SPDX-License-Identifier: BSD-2-Clause-FreeBSD
--
-- Copyright (c) 2019 Kyle Evans <kevans@FreeBSD.org>

local lfs = require("lfs")
local syscall = require("syscall")

local FreeBSDSyscall = {}

FreeBSDSyscall.__index = FreeBSDSyscall

function FreeBSDSyscall:parse_sysfile()
	local file = self.sysfile
	local config = self.config
	local commentExpr = "^%s*;.*"

	if file == nil then
		print "No file"
		return
	end

	self.syscalls = { }

	local fh = io.open(file)
	if fh == nil then
		print("Failed to open " .. file)
		return {}
	end

	local incs = ""
	local defs = ""
	local s
	for line in fh:lines() do
		line = line:gsub(commentExpr, "")		-- Strip any comments

		-- Note can't use pure pattern matching here because of the 's' test
		-- and this is shorter than a generic pattern matching pattern
		if line == nil or line == "" then
			-- nothing blank line or end of file
		elseif s ~= nil then
			-- If we have a partial system call object
			-- s, then feed it one more line
			if s:add(line) then
				-- append to syscall list
				table.insert(self.syscalls, s)
				s = nil
			end
		elseif line:match("^%s*%$") then
			-- nothing, obsolete $FreeBSD$ thing
		elseif line:match("^#%s*include") then
			incs = incs .. line .. "\n"
		elseif line:match("%%ABI_HEADERS%%") then
			local h= self.config.abi_headers
			if h ~= nil and h ~= "" then
				incs = incs .. h .. "\n"
			end
		elseif line:match("^#%s*define") then
			defs = defs .. line.. "\n"
		elseif line:match("^#") then
			abort(1, "Unsupported cpp op " .. line)
		else
			s = syscall:new()
			if s:add(line) then
				-- append to syscall list
				table.insert(self.syscalls, s)
				s = nil
			end
		end
	end
	if s ~= nil then
		abort(1, "Dangling system call at the end")
	end

	assert(io.close(fh))
	self.includes = incs
	self.defines = defs
end

function FreeBSDSyscall:new(obj)
	obj = obj or { }
	setmetatable(obj, self)
	self.__index = self

	obj:parse_sysfile()

	return obj
end

return FreeBSDSyscall
