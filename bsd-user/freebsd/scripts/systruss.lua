#!/usr/libexec/flua
--
-- SPDX-License-Identifier: BSD-2-Clause
--
-- Copyright (c) 2026 Warner Losh <imp@FreeBSD.org>
-- Copyright (c) 2024 Tyler Baxter <agge@FreeBSD.org>
-- Copyright (c) 2019 Kyle Evans <kevans@FreeBSD.org>
--

-- Add library root to the package path.
local path = arg[0]:gsub("/[^/]+.lua$", "")
package.path = package.path .. ";" .. path .. "/?.lua;" .. os.getenv('FREEBSD_SYSCALL_DIR') .. "/?.lua"

local FreeBSDSyscall = require("core.freebsd-syscall")
local generator = require("tools.generator")
local config = require("config")
local qemu = require("qemu")

-- File has not been decided yet; config will decide file.  Default defined as
-- /dev/null.
file = "/dev/stdout"

local lookup = {
--	["char *"] = "Name",
--	["char **"] = "StringArray",
	["void *"] = "Ptr",
	caddr_t = "Ptr",
	uid_t = "PUInt",
	int = "Int",
	unsigned = "Int",
	clockid_t = "Int",
	cpulevel_t = "Int",
	cpuwhich_t = "Int",
	cputsetid_t = "Int",
	size_t = "Sizet",
	ssize_t = "Sizet",
	intptr_t = "Long",
	uintptr_t = "Ulong",
	long = "Long",
	key_t = "Long",
	u_long = "Ulong",
	pid_t = "UInt",
	lwpid_t = "UInt",
	uint32_t = "UInt",
	mode_t = "Octal",
	off_t = "QuadHex",
	id_t = "QuadHex",
	idtype_t = "QuadHex",
	uint64_t = "QuadHex",
	dev_t = "QuadHex",
	semid_t = "Ptr",
	unsinged = "UInt",
	u_int = "UInt",
	uid_t = "UInt",
	gid_t = "UInt",
	["unsigned int"] = "UInt",
}

local known = {
	Rusage = 1,
	Msghdr = 1,
	Sockaddr = 1,
	Itimerval = 1,
	Timeval = 1,
	Stat11 = 1,
	Rlimit = 1,
	Pollfd = 1,
	Timespec = 1,
	Sigevent = 1,
	QuadHex = 1,
	Aiocb = 1,
	Siginfo = 1,
	Acltype = 1,
	Kevent11 = 1,
	Sigaction = 1,
	Sctpsndrcvinfo = 1,
	Stat = 1,
	StatFs = 1,
	Kevent = 1,
}

function string:startswith(start)
    return self:sub(1, #start) == start
end


function arg_type(arg)
	local t = arg.type
	local is_ptr = t:find("*")
	local is_const = t:startswith("const ")
	local out = ""
	local a = arg.annotation

	if a then
		if a:find("_In_") then
			out = "IN | "
		elseif a:find("_Out_") then
			out = "OUT | "
		elseif a:find("_Inout_") then
			out = "IN | OUT | "
		end
	end
	if is_const then
		t = t:sub(7)
	end
	if is_ptr and t:startswith("struct ") then
		local s = t:sub(8, -3)
		local ver, rest = s:match("^freebsd(%d+)_(%S+)")

		if ver and rest then
			s = rest:sub(1,1):upper() .. rest:sub(2) .. ver
		else
			s = s:sub(1,1):upper() .. s:sub(2)
		end
		if known[s] then
			return out .. s
		else
			return out .. "Ptr"
		end
	end
	local map = lookup[t]
	if map then
		return out .. map
	end
	if is_ptr then
		return out .. "Ptr"
	end
	-- final catch-all
	return out .. "LongHex /* " .. t .. " */"
end

function generate(tbl, config, fh)
	-- Grab the master system calls table.
	local s = tbl.syscalls

	-- Bind the generator to the parameter file.
	local gen = generator:new({}, fh)
	gen.storage_levels = {}	-- make sure storage is clear

	-- Write the generated preamble.
	gen:preamble("FreeBSD strace list\nNOTE: Use syscall numbers so we work on all the branches.")

	gen:write("const struct syscall_decode decoded_syscalls[] = {\n")
	for _, v in pairs(s) do
		-- Handle non-compat and compat (everything >= FREEBSD9):
		if v:bsd_user_impl() then
			ret_type = 1
			if v.alias == "lseek" then
				ret_type = 2
			end
			gen:write(string.format("    [ %d ] = { .name = \"%s\", .ret_type = %s, .nargs = %d,\n",
			    v.num, v.alias, ret_type, #v.args))
			if #v.args > 0 then
				gen:write("        {\n")
				offset = 0
				for _, arg in ipairs(v.args) do
					type = arg_type(arg)
					gen:write(string.format(
					    "            { %s, %d },\n", type, offset))
					offset = offset + 1
				end
				gen:write("        }\n")
			end
			gen:write(string.format("    }, /* %s %d */\n", v.alias, v.num))
		end
	end
	gen:write("};\n")
end


if #arg < 1 or #arg > 2 then
	error("usage: " .. arg[0] .. " syscall.master")
end

local sysfile = arg[1]

config.merge(None)
config.mergeCompat()

-- The parsed system call table.
local tbl = FreeBSDSyscall:new{sysfile = sysfile, config = config}

file = arg[2] or "/dev/stdout"
generate(tbl, config, file)
