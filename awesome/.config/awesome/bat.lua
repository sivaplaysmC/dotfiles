local wibox = require("wibox")
local awful = require("awful")

local bat = wibox.widget.textbox("BAT0: N/A")

---@param self wibox.widget.textbox
bat:connect_signal("bat_changed", function(self, vol)
	self.markup = "BAT0: " .. "<b>" .. vol .. "</b>"
end)

local bat_cmd = [[
pkill -f "/home/hknhmr/.config/awesome/bat.sh";
exec /home/hknhmr/.config/awesome/bat.sh
]]

awful.spawn.with_line_callback(bat_cmd, {
	stdout = function(line)
		bat:emit_signal("bat_changed", line)
	end,
})

return bat
