local wibox = require("wibox")
local awful = require("awful")
local naughty = require("naughty")

local volume = wibox.widget.textbox("VOL: N/A")


---@param self wibox.widget.textbox
volume:connect_signal("vol_changed", function(self, vol)
	self.markup = "VOL: " .. "<b>" .. vol .. "</b>"
end)

local volume_cmd = [[/home/hknhmr/.config/awesome/volume.sh]]

awful.spawn.with_line_callback(volume_cmd, {
	stdout = function(line)
		volume:emit_signal("vol_changed", line)
	end,
	exit = function(reason, code)
		local txt = "Process killed due to: " .. tostring(reason) .. " " .. tostring(code)
		naughty.notify({ text = txt })
	end,
})

return volume
