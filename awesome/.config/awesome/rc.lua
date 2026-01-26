-- If LuaRocks is installed, make sure that packages installed through it are
-- found (e.g. lgi). If LuaRocks is not installed, do nothing.
pcall(require, "luarocks.loader")

-- Standard awesome library
local gears = require("gears")
local awful = require("awful")
require("awful.autofocus")
-- Widget and layout library
local wibox = require("wibox")
-- Theme handling library
local beautiful = require("beautiful")
-- Notification library
local naughty = require("naughty")
local menubar = require("menubar")

local xresources = require("beautiful.xresources")
local dpi = xresources.apply_dpi
awesome.set_preferred_icon_size(64)

-- local hotkeys_popup = require("awful.hotkeys_popup")
-- -- Enable hotkeys help widget for VIM and other apps
-- -- when client with a matching name is opened:
-- require("awful.hotkeys_popup.keys")

-- {{{ Error handling
-- Check if awesome encountered an error during startup and fell back to
-- another config (This code will only ever execute for the fallback config)
if awesome.startup_errors then
	naughty.notify({
		preset = naughty.config.presets.critical,
		title = "Oops, there were errors during startup!",
		text = awesome.startup_errors,
	})
end

-- Handle runtime errors after startup
do
	local in_error = false
	awesome.connect_signal("debug::error", function(err)
		-- Make sure we don't go into an endless error loop
		if in_error then
			return
		end
		in_error = true

		naughty.notify({
			preset = naughty.config.presets.critical,
			title = "Oops, an error happened!",
			text = tostring(err),
		})
		in_error = false
	end)
end
-- }}}

-- {{{ Variable definitions
-- Themes define colours, icons, font and wallpapers.
beautiful.init("~/.config/awesome/themes/default/theme.lua")

-- This is used later as the default terminal and editor to run.
local terminal = "alacritty"

-- Default modkey.
-- Usually, Mod4 is the key with a logo between Control and Alt.
-- If you do not like this or do not have such a key,
-- I suggest you to remap Mod4 to another key using xmodmap or other tools.
-- However, you can use another modifier like Mod1, but it may interact with others.
local modkey = "Mod4"

-- Table of layouts to cover with awful.layout.inc, order matters.
awful.layout.layouts = {
	awful.layout.suit.floating,
	awful.layout.suit.tile,
	awful.layout.suit.max,
	awful.layout.suit.max.fullscreen,
	awful.layout.suit.magnifier,
	awful.layout.suit.corner.nw,
	-- awful.layout.suit.corner.ne,
	-- awful.layout.suit.corner.sw,
	-- awful.layout.suit.corner.se,
}
-- }}}

-- {{{ Menu
-- Create a launcher widget and a main menu
menubar.utils.terminal = terminal -- Set the terminal for applications that require it
-- }}}

-- {{{ Wibar
-- Create a textclock widget
local mytextclock = wibox.widget.textclock("%a %b %d, <b>%H:%M:%S</b>", 1)

-- local whoami = wibox.widget.textbox("hknhmr @ outer-heaven")

-- local fifo_widget = require("fifo_textbox")
local sss = require("script_textbox")

local volume = sss("/home/hknhmr/.config/awesome/volume.sh")
local bright = sss("/home/hknhmr/.config/awesome/bright.sh")

---@type fun(self: wibox.widget.textbox, text: string)
local wifi_setter = function(self, text)
	if text == "NOWIFI" or text == "" then
		naughty.notify({ title = "WIFI", text = "No wifi. Hope you got ethernet :)" })
		self.markup = "<b>NOWIFI</b>"
		return
	end

	local ap_name, ip_addr = text:match("^(.*)%s(%S+)$")

	if not ap_name or not ip_addr then
		naughty.notify({ title = "WIFI", text = "No wifi. Hope you got ethernet :)" })
		self.markup = "<b>WIFI???</b>"
		return
	end

	self.markup = "<b>" .. ap_name .. "</b>: " .. ip_addr
end

local wifi = sss("/home/hknhmr/.config/awesome/wifi.sh", wifi_setter)

---@type fun(self: wibox.widget.textbox, text: string)
local bat_setter = function(self, text)
	local split = gears.string.split(text, " ")
	local percent = tonumber(split[1])
	local status = tostring(split[2])

	if percent < 15 and status ~= "+" then
		naughty.notify({
			preset = naughty.config.presets.critical,
			title = "Low battery!",
			text = "Charge the damn battery. It's at " .. tostring(percent) .. "%.",
		})
	end

	local res = "BAT0: <b>" .. tostring(percent) .. "%" .. status .. "</b>"
	self.markup = res
end
local bat = sss("/home/hknhmr/.config/awesome/bat.sh", bat_setter)

-- Create a wibox for each screen and add it
local taglist_buttons = {
	awful.button({}, 1, function(t)
		t:view_only()
	end),
}

local tasklist_buttons = {
	awful.button({}, 1, function(c)
		if c == client.focus then
			c.minimized = true
		else
			c:emit_signal("request::activate", "tasklist", { raise = true })
		end
	end),
	awful.button({}, 3, function()
		awful.menu.client_list({ theme = { width = 250 } })
	end),
}

local function set_wallpaper(s)
	-- Wallpaper
	if beautiful.wallpaper then
		local wallpaper = beautiful.wallpaper
		-- If wallpaper is a function, call it with the screen
		if type(wallpaper) == "function" then
			wallpaper = wallpaper(s)
		end
		gears.wallpaper.fit(wallpaper, s)
	end
end

awful.screen.connect_for_each_screen(function(s)
	-- Wallpaper
	set_wallpaper(s)

	-- Each screen has its own tag table.
	awful.tag({ "1", "2", "3", "4", "5", "6", "7", "8", "9" }, s, awful.layout.layouts[1])

	-- Create an imagebox widget which will contain an icon indicating which layout we're using.
	-- We need one layoutbox per screen.
	s.mylayoutbox = wibox.container.margin(awful.widget.layoutbox(s), 8, 8, 8, 8)

	s.mylayoutbox:buttons({
		awful.button({}, 1, function()
			awful.layout.inc(1)
		end),
		awful.button({}, 3, function()
			awful.layout.inc(-1)
		end),
	})

	-- Create a taglist widget
	s.tagss = awful.widget.taglist({
		screen = s,
		filter = awful.widget.taglist.filter.all,
		buttons = taglist_buttons,

		widget_template = {
			{
				{
					{
						id = "text_role",
						widget = wibox.widget.textbox,
						font = "JetBrainsMono Nerd Font Bold 11",
					},
					layout = wibox.layout.fixed.horizontal,
				},
				left = 8,
				right = 8,
				widget = wibox.container.margin,
			},
			id = "background_role",
			widget = wibox.container.background,
			---@diagnostic disable-next-line: unused-local
			update_callback = function(self, c3, index, objects)
				-- naughty.notify({ text = tostring(index) })
				self:get_children_by_id("text_role")[1].markup = "<b> " .. index .. " </b>"
			end,
		},
	})

	s.mytitle = awful.widget.tasklist({
		screen = s,
		filter = awful.widget.tasklist.filter.focused,
		buttons = tasklist_buttons,

		widget_template = {
			{
				{
					{
						{
							id = "icon_role",
							widget = wibox.widget.imagebox,
						},
						top = 8,
						bottom = 8,
						widget = wibox.container.margin,
					},
					{
						id = "text_role",
						widget = wibox.widget.textbox,
					},
					spacing = 10,
					layout = wibox.layout.fixed.horizontal,
				},
				left = 10,
				right = 10,
				widget = wibox.container.margin,
			},
			id = "background_role",
			widget = wibox.container.background,
		},
	})

	-- Create the wibox
	s.mywibox = awful.wibar({ position = "top", screen = s, height = 35 })

	s.systray = wibox.widget({
		wibox.widget.systray(true),
		margins = 5,
		widget = wibox.container.margin,
	})

	-- Add widgets to the wibox
	s.mywibox:setup({
		layout = wibox.layout.align.horizontal,
		{ -- Left widgets
			layout = wibox.layout.fixed.horizontal,
			s.tagss,
			s.mylayoutbox,
		},
		s.mytitle, -- Middle widget
		{
			{
				layout = wibox.layout.fixed.horizontal,
				spacing = 24,
				spacing_widget = {
					widget = wibox.widget.separator,
					orientation = "vertical",
					thickness = 1,
					span_ratio = 0.6,
				},
				s.systray,
				bat,
				wifi,
				bright,
				volume,
				mytextclock,
			},
			widget = wibox.container.margin,
			top = 3,
			bottom = 3,
			right = 10,
			left = 10,
		},
	})
end)
-- }}}

-- {{{ Key bindings
GlobalKeys = gears.table.join(
	awful.key({ modkey }, "Left", awful.tag.viewprev, { description = "view previous", group = "tag" }),
	awful.key({ modkey }, "Right", awful.tag.viewnext, { description = "view next", group = "tag" }),
	awful.key({ modkey }, "Escape", awful.tag.history.restore, { description = "go back", group = "tag" }),

	awful.key({ modkey }, "j", function()
		awful.client.focus.byidx(1)
	end, { description = "focus next by index", group = "client" }),

	awful.key({ modkey }, "k", function()
		awful.client.focus.byidx(-1)
	end, { description = "focus previous by index", group = "client" }),
	-- Layout manipulation
	awful.key({ modkey, "Shift" }, "j", function()
		awful.client.swap.byidx(1)
	end, { description = "swap with next client by index", group = "client" }),
	awful.key({ modkey, "Shift" }, "k", function()
		awful.client.swap.byidx(-1)
	end, { description = "swap with previous client by index", group = "client" }),
	awful.key({ modkey, "Control" }, "j", function()
		awful.screen.focus_relative(1)
	end, { description = "focus the next screen", group = "screen" }),
	awful.key({ modkey, "Control" }, "k", function()
		awful.screen.focus_relative(-1)
	end, { description = "focus the previous screen", group = "screen" }),
	awful.key({ modkey }, "u", awful.client.urgent.jumpto, { description = "jump to urgent client", group = "client" }),
	-- awful.key({ modkey }, "Tab", function()
	-- 	awful.client.focus.history.previous()
	-- 	if client.focus then
	-- 		client.focus:raise()
	-- 	end
	-- end, { description = "go back", group = "client" }),

	-- Standard program
	awful.key({ modkey }, "Return", function()
		awful.spawn(terminal)
	end, { description = "open a terminal", group = "launcher" }),
	awful.key({ modkey, "Control" }, "r", awesome.restart, { description = "reload awesome", group = "awesome" }),
	awful.key({ modkey, "Shift" }, "q", awesome.quit, { description = "quit awesome", group = "awesome" }),
	awful.key({ modkey, "Shift" }, "s", function()
		awful.spawn("/bin/flameshot gui")
	end, { description = "quit awesome", group = "awesome" }),

	awful.key({ modkey }, "l", function()
		awful.tag.incmwfact(0.05)
	end, { description = "increase master width factor", group = "layout" }),
	awful.key({ modkey }, "h", function()
		awful.tag.incmwfact(-0.05)
	end, { description = "decrease master width factor", group = "layout" }),
	awful.key({ modkey, "Shift" }, "h", function()
		awful.tag.incnmaster(1, nil, true)
	end, { description = "increase the number of master clients", group = "layout" }),
	awful.key({ modkey, "Shift" }, "l", function()
		awful.tag.incnmaster(-1, nil, true)
	end, { description = "decrease the number of master clients", group = "layout" }),
	awful.key({ modkey, "Control" }, "h", function()
		awful.tag.incncol(1, nil, true)
	end, { description = "increase the number of columns", group = "layout" }),
	awful.key({ modkey, "Control" }, "l", function()
		awful.tag.incncol(-1, nil, true)
	end, { description = "decrease the number of columns", group = "layout" }),
	awful.key({ modkey }, "space", function()
		awful.layout.inc(1)
	end, { description = "select next", group = "layout" }),
	awful.key({ modkey, "Shift" }, "space", function()
		awful.layout.inc(-1)
	end, { description = "select previous", group = "layout" }),

	awful.key({ modkey, "Control" }, "n", function()
		local c = awful.client.restore()
		-- Focus restored client
		if c then
			c:emit_signal("request::activate", "key.unminimize", { raise = true })
		end
	end, { description = "restore minimized", group = "client" }),

	-- Menubar
	awful.key({ modkey }, "p", function()
		awful.spawn("rofi -show drun")
	end, { description = "show the menubar", group = "launcher" }),

	awful.key({ modkey, "Shift" }, "p", function()
		awful.spawn("/home/hknhmr/.local/bin/getpass")
	end, { description = "show menubar", group = "launcher" }),

	awful.key({ modkey }, "Tab", function()
		awful.spawn("rofi -show window")
	end, { description = "show the menubar", group = "launcher" }),

	-- Example using brightnessctl
	awful.key({}, "XF86MonBrightnessUp", function()
		awful.spawn.with_shell("brightnessctl set +5%")
	end),
	awful.key({}, "XF86MonBrightnessDown", function()
		awful.spawn.with_shell("brightnessctl set 5%-")
	end),

	awful.key({}, "XF86AudioRaiseVolume", function()
		awful.spawn.with_shell("wpctl set-volume @DEFAULT_SINK@ 1%+")
	end, { description = "volume up", group = "hotkeys" }),

	awful.key({}, "XF86AudioLowerVolume", function()
		awful.spawn.with_shell("wpctl set-volume @DEFAULT_SINK@ 1%-")
	end, { description = "volume down", group = "hotkeys" }),

	awful.key({}, "XF86AudioMute", function()
		awful.spawn.with_shell("wpctl set-mute @DEFAULT_SINK@ toggle")
	end, { description = "toggle mute", group = "hotkeys" }),

	awful.key({}, "XF86AudioMicMute", function()
		awful.spawn.with_shell("wpctl set-mute @DEFAULT_SOURCE@ toggle")
	end, { description = "toggle mic mute", group = "hotkeys" }),

	awful.key({ modkey }, "b", function()
		mouse.screen.mywibox.visible = not mouse.screen.mywibox.visible
	end)
)

local clientkeys = gears.table.join(
	awful.key({ modkey }, "f", function(c)
		c.fullscreen = not c.fullscreen
		c:raise()
	end, { description = "toggle fullscreen", group = "client" }),
	awful.key({ modkey }, "q", function(c)
		c:kill()
	end, { description = "close", group = "client" }),
	awful.key(
		{ modkey, "Control" },
		"space",
		awful.client.floating.toggle,
		{ description = "toggle floating", group = "client" }
	),
	awful.key({ modkey, "Control" }, "Return", function(c)
		c:swap(awful.client.getmaster())
	end, { description = "move to master", group = "client" }),
	awful.key({ modkey }, "o", function(c)
		c:move_to_screen()
	end, { description = "move to screen", group = "client" }),
	awful.key({ modkey }, "t", function(c)
		c.ontop = not c.ontop
	end, { description = "toggle keep on top", group = "client" }),
	awful.key({ modkey }, "n", function(c)
		-- The client currently has the input focus, so it cannot be
		-- minimized, since minimized clients can't have the focus.
		c.minimized = true
	end, { description = "minimize", group = "client" }),
	awful.key({ modkey }, "m", function(c)
		if c.maximized then
			awful.titlebar.show(c)
		else
			awful.titlebar.hide(c)
		end
		c.maximized = not c.maximized
		c:raise()
	end, { description = "(un)maximize", group = "client" })
)

-- Bind all key numbers to tags.
-- Be careful: we use keycodes to make it work on any keyboard layout.
-- This should map on the top row of your keyboard, usually 1 to 9.
for i = 1, 9 do
	GlobalKeys = gears.table.join(
		GlobalKeys,
		-- View tag only.
		awful.key({ modkey }, "#" .. i + 9, function()
			local screen = awful.screen.focused()
			local tag = screen.tags[i]
			if tag then
				tag:view_only()
			end
		end, { description = "view tag #" .. i, group = "tag" }),
		-- Toggle tag display.
		awful.key({ modkey, "Control" }, "#" .. i + 9, function()
			local screen = awful.screen.focused()
			local tag = screen.tags[i]
			if tag then
				awful.tag.viewtoggle(tag)
			end
		end, { description = "toggle tag #" .. i, group = "tag" }),
		-- Move client to tag.
		awful.key({ modkey, "Shift" }, "#" .. i + 9, function()
			if client.focus then
				local tag = client.focus.screen.tags[i]
				if tag then
					client.focus:move_to_tag(tag)
				end
			end
		end, { description = "move focused client to tag #" .. i, group = "tag" }),
		-- Toggle tag on focused client.
		awful.key({ modkey, "Control", "Shift" }, "#" .. i + 9, function()
			if client.focus then
				local tag = client.focus.screen.tags[i]
				if tag then
					client.focus:toggle_tag(tag)
				end
			end
		end, { description = "toggle focused client on tag #" .. i, group = "tag" })
	)
end

local clientbuttons = gears.table.join(
	awful.button({}, 1, function(c)
		c:emit_signal("request::activate", "mouse_click", { raise = true })
	end),
	awful.button({ modkey }, 1, function(c)
		c:emit_signal("request::activate", "mouse_click", { raise = true })
		awful.mouse.client.move(c)
	end),
	awful.button({ modkey }, 3, function(c)
		c:emit_signal("request::activate", "mouse_click", { raise = true })
		awful.mouse.client.resize(c)
	end)
)

-- Set keys
root.keys(GlobalKeys)
-- }}}

-- {{{ Rules
-- Rules to apply to new clients (through the "manage" signal).
awful.rules.rules = {
	-- All clients will match this rule.
	-- god forgive me for the two ugliest rules I'm going to write.
	-- Goal: I don't want transient_for clients to have a placement -
	-- Ideally, they should sit wherever they want.
	--
	-- but this catch-all rule is too wide, and as a result pop-ups for ghidra
	-- (like the autocomplete window, hover window, etc.) are placed on the top-left
	--
	-- To fix this madness,
	-- 1. Create exception so that dialogs, popups, and transient windows are not touched by awesome.
	-- 2. Create a rule ONLY for dialogs, giving them perks like normal windows.
	{
		rule = {},
		except_any = {
			type = { "dialog" },
			transient_for = { true },
			role = { "pop-up" },
		},
		properties = {
			border_width = beautiful.border_width,
			border_color = beautiful.border_normal,
			titlebars_enabled = true,
			floating = true,
			focus = awful.client.focus.filter,
			raise = true,
			keys = clientkeys,
			buttons = clientbuttons,
			screen = awful.screen.preferred,
			placement = function(c, _args)
				_ = _args
				awful.placement.centered(c)
				awful.placement.no_overlap(c)
				awful.placement.no_offscreen(c)
			end,
		},
	},

	-- ts is to let dialog windows position themselves.
	-- Ideally, we only want windows of ghidra to have this unconstrained placement -
	-- no harm in having to fix this later.
	{
		rule = {
			type = "dialog",
		},
		properties = {
			border_width = beautiful.border_width,
			border_color = beautiful.border_normal,
			titlebars_enabled = true,
			floating = true,
			focus = awful.client.focus.filter,
			raise = true,
			keys = clientkeys,
			buttons = clientbuttons,
			screen = awful.screen.preferred,
		},
	},

	{
		rule = {
			maximized = true,
		},
		properties = {
			titlebars_enabled = false,
		},
	},

	-- Floating clients.
	{
		rule_any = {
			instance = {
				"DTA",
				"copyq",
				"pinentry",
			},
			class = {
				"pavucontrol",
				"Arandr",
				"Blueman-manager",
				"Gpick",
				"Kruler",
				"MessageWin", -- kalarm.
				"Sxiv",
				"Tor Browser", -- Needs a fixed window size to avoid fingerprinting by screen size.
				"Wpa_gui",
				"veromix",
				"xtightvncviewer",
			},

			-- Note that the name property shown in xprop might be set slightly after creation of the client
			-- and the name shown there might not match defined rules here.
			name = {
				"Event Tester", -- xev.
			},
			role = {
				"AlarmWindow", -- Thunderbird's calendar.
				"ConfigManager", -- Thunderbird's about:config.
				"pop-up", -- e.g. Google Chrome's (detached) Developer Tools.
			},
		},
		properties = { floating = true },
	},

	{
		rule = {
			instance = "copyq",
		},
		properties = {
			titlebars_enabled = false,
			placement = function(c)
				awful.placement.next_to_mouse(c)
				awful.placement.no_offscreen(c)
			end,
		},
	},

	{
		rule_any = {
			instance = { "lxpolkit", "pinentry-gtk" },
		},
		properties = {
			placement = function(c)
				awful.placement.align(c, { position = "centered" })
			end,
		},
	},
}

-- }}}

-- {{{ Signals
-- Signal function to execute when a new client appears.
client.connect_signal("request::manage", function(c)
	-- Set the windows at the slave,
	-- i.e. put it at the end of others instead of setting it master.
	-- if not awesome.startup then awful.client.setslave(c) end

	-- if awesome.startup and not c.size_hints.user_position and not c.size_hints.program_position then
	-- 	-- Prevent clients from being unreachable after screen count changes.
	-- 	awful.placement.no_offscreen(c)
	-- end
end)

---@param c client
-- Add a titlebar if titlebars_enabled is set to true in the rules.
client.connect_signal("request::titlebars", function(c)
	-- Never decorate transient child dialogs
	if c.requests_no_titlebar then
		return
	end

	-- if c.maximized then
	-- 	return
	-- end

	-- buttons for the titlebar
	local buttons = gears.table.join(
		awful.button({}, 1, function()
			c:emit_signal("request::activate", "titlebar", { raise = true })
			awful.mouse.client.move(c)
		end),
		awful.button({}, 3, function()
			c:emit_signal("request::activate", "titlebar", { raise = true })
			awful.mouse.client.resize(c)
		end)
	)

	awful.titlebar(c):setup({
		{ -- Left
			{
				{
					awful.titlebar.widget.iconwidget(c),
					layout = wibox.layout.fixed.horizontal,
				},
				widget = wibox.container.margin,
				margins = 5,
			},
			layout = wibox.layout.fixed.horizontal,
			spacing = 10,
		},
		{
			{
				widget = awful.titlebar.widget.titlewidget(c),
			},
			widget = wibox.container.margin,
			margins = {
				left = 3,
			},
		},
		{ -- Right
			{
				awful.titlebar.widget.floatingbutton(c),
				awful.titlebar.widget.maximizedbutton(c),
				awful.titlebar.widget.stickybutton(c),
				awful.titlebar.widget.ontopbutton(c),
				awful.titlebar.widget.closebutton(c),

				spacing = dpi(10),
				layout = wibox.layout.fixed.horizontal(),
			},
			right = 10,
			top = 5,
			bottom = 5,
			widget = wibox.container.margin,
		},
		buttons = buttons,
		layout = wibox.layout.align.horizontal(),
	})
end)

-- Enable sloppy focus, so that focus follows mouse.
client.connect_signal("mouse::enter", function(c)
	c:emit_signal("request::activate", "mouse_enter", { raise = false })
end)

client.connect_signal("focus", function(c)
	c.border_color = beautiful.border_focus
end)
client.connect_signal("unfocus", function(c)
	c.border_color = beautiful.border_normal
end)
-- }}}

client.connect_signal("property::fullscreen", function(c)
	local tb_height = awful.titlebar(c).height --Custom Titlebar height
		or math.floor(tonumber(beautiful.get_font_height(beautiful.get().font) * 1.5)) --Default Titlebar height
		or 45 --Failsafe
	if c.fullscreen then
		c.height = c.height + tb_height
		awful.titlebar.hide(c)
	else
		c.height = c.height - tb_height
		awful.titlebar.show(c)
	end
end)
