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

function FreeBSDSyscall:new(sysfile, config)
	local this = {
		sysfile = sysfile,
		config = config,
	}
	setmetatable(this, self)

	return this
end

return FreeBSDSyscall
