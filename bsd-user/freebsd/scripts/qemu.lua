#!/usr/libexec/flua
--
-- SPDX-License-Identifier: BSD-2-Clause
--
-- Copyright (c) 2026 Warner Losh <imp@bsdimp.com>
--

-- bsd-user specific helper routines

local syscall = require("core.syscall")
local qemu = {}

-- What's the target type for the foo_args struct. We may need to rename this to
-- something else once we're doing the struct remapping (which will want to turn
-- struct foo *into struct target_foo * anyeay).  And yes, it does kinda suck to
-- have this list here, but it's only primary types, so it's unlikely to
-- grow. All FreeBSD defined types are handled in os-types.h.
-- XXX is this something that we can do with the config file feature? Reevaluate
-- when we do 32-bit abis
function qemu.target_type(t)
	if t:find("*") then
		return "abi_long"
	elseif t == "short" then
		return "abi_short"
	elseif t == "u_short" then
		return "abi_ushort"
	elseif t == "int" then
		return "abi_int"
	elseif t == "u_int" or t == "unsigned" or t == "unsigned int" then
		return "abi_uint"
	elseif t == "long" then
		return "abi_long"
	elseif t == "u_long" then
		return "abi_ulong"
	elseif t:match("uint%d+_t") or t:match("int%d+_t") or t:match("u_int%d+_t") then
		return t
	end
	return "target_" .. t
end

local freebsd_compat_level = 9

function syscall.struct_args(self)
	return "target_" .. self:symbol() .. "_args"
end

function syscall.bsd_user_impl(self)
	-- NODEF     A system call that's included, but that FreeBSD doesn't
	--           add to the system call tables. Used to reserve system calls
	-- SYSMUX    system or __system
	-- NOPROTO   not used, but basically means just make SYS_xxxx for this
	-- NOLIB     Don't add a library call, but practically just used on yield()
	--           for reasons unknown (why is that even still there?)
	-- NOTSTATIC Also used with NODEF, someties, to reserve a system call for
	--           a third party. FreeBSD only uses it for nnpfs_syscall, which
	--           also isn't properly annotated.
	return (self:native() or self:compatLevel() >=freebsd_compat_level) and
		not self.type.NODEF and not self.type.SYSMUX and
		not self.type.NOPROTO and not self.type.NOLIB and
		not self.type.NOTSTATIC
end

-- Function to reverser iterate
function qemu.ripairs(t)
    return function(t, i)
        i = i - 1
        if i > 0 then
            return i, t[i]
        end
    end, t, #t + 1
end

return qemu
