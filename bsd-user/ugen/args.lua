--
-- SPDX-License-Identifier: BSD-2-Clause
--
-- Copyright (c) 2023 Warner Losh <imp@bsdimp.com>
--

local args = {}

args.__index = args

function args:new(obj, line)
	obj = obj or { }
	setmetatable(obj, self)
	self.__index = self

	self.arg = line

	return obj
end

return args

