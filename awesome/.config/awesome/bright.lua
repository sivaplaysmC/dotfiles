local wibox = require("wibox")
local awful = require("awful")
local naughty = require("naughty")

local bright = wibox.widget.textbox("LIT: N/A")

---@param self wibox.widget.textbox
bright:connect_signal("brightness_changed", function(self, bl)
	self.markup = "LIT: " .. "<b>" .. bl .. "</b>"
end)

local bright_cmd = [[
pkill -f "/home/hknhmr/.config/awesome/bright.sh";
exec /home/hknhmr/.config/awesome/bright.sh
]]

awful.spawn.with_line_callback(bright_cmd, {
	stdout = function(line)
		naughty.notify({ text = line })
		bright:emit_signal("bright_changed", line)
	end,
})

return bright
