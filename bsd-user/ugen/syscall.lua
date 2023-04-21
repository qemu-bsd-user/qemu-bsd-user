--
-- SPDX-License-Identifier: BSD-2-Clause
--
-- Copyright (c) 2023 Warner Losh <imp@bsdimp.com>
--

local syscall = {}

syscall.__index = syscall

function syscall:add(line)
	local words = {}

	for w in line:gmatch("%S+") do
		table.insert(words, w)
	end

	if self.num == nil then
		-- sort out range somehow XXX
		-- Also, where to put validation of no skipped syscall #? XXX
		self.num = words[1]
		self.audit = words[2]
		self.type = words[3]
		self.name = words[4]
		return self.name ~= "{"
	end

	if self.name == "{" then
		-- Expect line is "type syscall(" or "type syscall(void);"
		if #words ~= 2 then
			abort(1, "Malformed line " .. line)
		end
		self.rettype = words[1]
		self.name = words[2]:gsub("%(.*$", "")
		if words[2]:match("%);$") then
			self.expect_rbrace = true
		end
		return false
	end

	if not self.expect_rparen and not self.expect_rbrace then
		-- We're looking for (another) argument
		-- xxx copout for the moment and just snarf the argument
		-- some have trailing , on last arg
		if line:match("%);$") then
			print("Warning: " .. self.name .. " malformed args")
			self.expect_rbrace = true
			return false
		end

		local arg = line:gsub("^%s+","")
		table.insert(self.args, arg)
		if not arg:match(",$") or arg == "..." then
			self.expect_rparen = true
		end
		return false
	end

	assert(self.expect_rparen ~= self.expect_rbrace) -- They nest... so only one is true

	if self.expect_rparen then
		if not line:match("%);$") then
			abort(1, "Expected ');' found '" .. line .. "' instead.")
		end
		self.expect_rparen = false
		self.expect_rbrace = true
		return false
	end

	if self.expect_rbrace then
		if not line:match("}$") then
			abort(1, "Expected '}' found '" .. line .. "' instead.")
		end
		self.expect_brace = false
		return true
	end

	abort(1, "This is impossible: " .. line)
	return true -- object is complete
end

function syscall:new(obj)
	obj = obj or { }
	setmetatable(obj, self)
	self.__index = self

	self.expect_rparen = false
	self.expect_rbrace = false
	self.args = { }

	return obj
end

return syscall

