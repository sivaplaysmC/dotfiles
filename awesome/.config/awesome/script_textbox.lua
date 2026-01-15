local wibox = require("wibox")
local awful = require("awful")
local naughty = require("naughty")

--- Creates a textbox widget that reads live output from a script
---@param script string Full path to script
---@param setter fun(wibox.widget.textbox, text) Optional setter function
---@return wibox.widget.textbox
local function script_textbox(script, setter)
	setter = setter
		or function(self, text)
			self.markup = text
		end

	local widget = wibox.widget.textbox("N/A")

	-- Update function
	widget:connect_signal("script::push", setter)

	-- Spawn the command
	awful.spawn.with_line_callback(script, {
		stdout = function(line)
			widget:emit_signal("script::push", line)
		end,
		exit = function(reason, code)
			naughty.notify({
				title = "Script exited",
				text = script .. " -> " .. tostring(reason) .. " " .. tostring(code),
			})
		end,
	})

	return widget
end

return script_textbox
