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

-- Code to read in the config file that drives this. Since we inherit from the
-- FreeBSD makesyscall.sh legacy, all config is done through a config file that
-- sets a number of varibale (as noted below, it used to be a .sh file that was
-- sourced in. This dodges the need to write a command line parser.

-- XXX Not sure what else needs to be here, or if we should 'hoist' the merging of
-- the map this returns into the global config map since that's likely to be the
-- same everywhere.

local config = {}

local util = require("util")

-- config looks like a shell script; in fact, the previous makesyscalls.sh
-- script actually sourced it in.  It had a pretty common format, so we should
-- be fine to make various assumptions
function config.process(file)
	local cfg = {}
	local comment_line_expr = "^%s*#.*"
	-- We capture any whitespace padding here so we can easily advance to
	-- the end of the line as needed to check for any trailing bogus bits.
	-- Alternatively, we could drop the whitespace and instead try to
	-- use a pattern to strip out the meaty part of the line, but then we
	-- would need to sanitize the line for potentially special characters.
	local line_expr = "^([%w%p]+%s*)=(%s*[`\"]?[^\"`]*[`\"]?)"

	if not file then
		return nil, "No file given"
	end

	local fh = assert(io.open(file))

	for nextline in fh:lines() do
		-- Strip any whole-line comments
		nextline = nextline:gsub(comment_line_expr, "")
		-- Parse it into key, value pairs
		local key, value = nextline:match(line_expr)
		if key ~= nil and value ~= nil then
			local kvp = key .. "=" .. value
			key = util.trim(key)
			value = util.trim(value)
			local delim = value:sub(1,1)
			if delim == '"' then
				local trailing_context

				-- Strip off the key/value part
				trailing_context = nextline:sub(kvp:len() + 1)
				-- Strip off any trailing comment
				trailing_context = trailing_context:gsub("#.*$",
				    "")
				-- Strip off leading/trailing whitespace
				trailing_context = util.trim(trailing_context)
				if trailing_context ~= "" then
					print(trailing_context)
					abort(1, "Malformed line: " .. nextline)
				end

				value = trim(value, delim)
			else
				-- Strip off potential comments
				value = value:gsub("#.*$", "")
				-- Strip off any padding whitespace
				value = trim(value)
				if value:match("%s") then
					abort(1, "Malformed config line: " ..
					    nextline)
				end
			end
			cfg[key] = value
		elseif not nextline:match("^%s*$") then
			-- Make sure format violations don't get overlooked
			-- here, but ignore blank lines.  Comments are already
			-- stripped above.
			abort(1, "Malformed config line: " .. nextline)
		end
	end

	assert(io.close(fh))
	return cfg
end

return config
