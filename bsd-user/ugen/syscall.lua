--
-- SPDX-License-Identifier: BSD-2-Clause
--
-- Copyright (c) 2023 Warner Losh <imp@bsdimp.com>
--

local syscall = {}

syscall.__index = syscall

function syscall:add(line)
	local words = line:gmatch("%S+")
-- XXX start here --
	return true -- object is complete
end

function syscall:new(obj)
	obj = obj or { }
	setmetatable(obj, self)
	self.__index = self

	return obj
end

return syscall

