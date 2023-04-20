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

local FreeBSDSyscall = {}

FreeBSDSyscall.__index = FreeBSDSyscall

function FreeBSDSyscall:new(obj, sysfile, config)
	local this = {
		sysfile = sysfile,
		config = config,
	}
	obj = obj or this
	setmetatable(obj, self)
	self.__index = self
	
	return obj
end

return FreeBSDSyscall
