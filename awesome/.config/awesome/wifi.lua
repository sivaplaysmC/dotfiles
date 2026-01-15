local wibox = require("wibox")
local awful = require("awful")

local wifi = wibox.widget.textbox("wifi0: N/A")

---@param self wibox.widget.textbox
wifi:connect_signal("wifi_changed", function(self, bl)
	self.markup = bl
end)

local wifi_cmd = [[
pkill -f "/home/hknhmr/.config/awesome/wifi.sh";
exec /home/hknhmr/.config/awesome/wifi.sh
]]

awful.spawn.with_line_callback(wifi_cmd, {
	stdout = function(line)
		wifi:emit_signal("wifi_changed", line)
	end,
})

return wifi
