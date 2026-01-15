---------------------------
-- Default awesome theme --
---------------------------

local theme_assets = require("beautiful.theme_assets")
local xresources = require("beautiful.xresources")
local dpi = xresources.apply_dpi

local gfs = require("gears.filesystem")
local themes_path = gfs.get_themes_dir()

local theme = {}

theme.font = "JetbrainsMono Nerd Font Propo 10"

-- Neovim default dark palette
local colors = {
	foreground = "#e0e2ea",
	background = "#14161b",

	blue = "#005078",
	cyan = "#007676",
	green = "#015825",
	grey1 = "#0a0b10",
	grey2 = "#1c1d23",
	grey3 = "#2c2e33",
	grey4 = "#4f5258",
	magenta = "#4c0049",
	red = "#5e0009",
	yellow = "#6e5600",
}
theme.colors = colors

-- Backgrounds
theme.bg_normal = colors.background
theme.bg_focus = colors.grey2
theme.bg_urgent = colors.red
theme.bg_minimize = colors.grey3
theme.bg_systray = theme.bg_normal

-- Foregrounds
theme.fg_normal = colors.foreground
theme.fg_focus = colors.foreground
theme.fg_urgent = colors.foreground
theme.fg_minimize = colors.foreground

-- Borders
theme.border_normal = colors.grey3
theme.border_focus = colors.blue
theme.border_marked = colors.magenta


-- There are other variable sets
-- overriding the default one when
-- defined, the sets are:
-- taglist_[bg|fg]_[focus|urgent|occupied|empty|volatile]
-- tasklist_[bg|fg]_[focus|urgent]
-- titlebar_[bg|fg]_[normal|focus]
-- tooltip_[font|opacity|fg_color|bg_color|border_width|border_color]
-- mouse_finder_[color|timeout|animate_timeout|radius|factor]
-- prompt_[fg|bg|fg_cursor|bg_cursor|font]
-- hotkeys_[bg|fg|border_width|border_color|shape|opacity|modifiers_fg|label_bg|label_fg|group_margin|font|description_font]
-- Example:
--theme.taglist_bg_focus = "#ff0000"

-- Generate taglist squares:
local taglist_square_size = dpi(7)
theme.taglist_squares_sel = theme_assets.taglist_squares_sel(taglist_square_size, theme.fg_normal)
theme.taglist_squares_unsel = theme_assets.taglist_squares_unsel(taglist_square_size, theme.fg_normal)
theme.taglist_bg_focus = colors.blue
theme.taglist_font = "JetbrainsMono Nerd Font Propo Bold 10"

-- Variables set for theming notifications:
-- notification_font
-- notification_[bg|fg]
-- notification_[width|height|margin]
-- notification_[border_color|border_width|shape|opacity]

-- Variables set for theming the menu:
-- menu_[bg|fg]_[normal|focus]
-- menu_[border_color|border_width]
theme.menu_submenu_icon = themes_path .. "default/submenu.png"
theme.menu_height = dpi(15)
theme.menu_width = dpi(100)

theme.border_width = dpi(3)

-- You can add as many variables as
-- you wish and access them by using
-- beautiful.variable in your rc.lua
--theme.bg_widget = "#cc0000"

-- Define the image to load
theme.titlebar_close_button_focus = "/home/hknhmr/.config/awesome/themes/" .. "default/titlebar/default/close_focus.png"
theme.titlebar_close_button_normal = "/home/hknhmr/.config/awesome/themes/"
	.. "default/titlebar/default/close_normal.png"
theme.titlebar_floating_button_focus_active = "/home/hknhmr/.config/awesome/themes/"
	.. "default/titlebar/default/floating_focus_active.png"
theme.titlebar_floating_button_focus_inactive = "/home/hknhmr/.config/awesome/themes/"
	.. "default/titlebar/default/floating_focus_inactive.png"
theme.titlebar_floating_button_normal_active = "/home/hknhmr/.config/awesome/themes/"
	.. "default/titlebar/default/floating_normal_active.png"
theme.titlebar_floating_button_normal_inactive = "/home/hknhmr/.config/awesome/themes/"
	.. "default/titlebar/default/floating_normal_inactive.png"
theme.titlebar_maximized_button_focus_active = "/home/hknhmr/.config/awesome/themes/"
	.. "default/titlebar/default/maximized_focus_active.png"
theme.titlebar_maximized_button_focus_inactive = "/home/hknhmr/.config/awesome/themes/"
	.. "default/titlebar/default/maximized_focus_inactive.png"
theme.titlebar_maximized_button_normal_active = "/home/hknhmr/.config/awesome/themes/"
	.. "default/titlebar/default/maximized_normal_active.png"
theme.titlebar_maximized_button_normal_inactive = "/home/hknhmr/.config/awesome/themes/"
	.. "default/titlebar/default/maximized_normal_inactive.png"
theme.titlebar_minimize_button_focus = "/home/hknhmr/.config/awesome/themes/"
	.. "default/titlebar/default/minimize_focus.png"
theme.titlebar_minimize_button_normal = "/home/hknhmr/.config/awesome/themes/"
	.. "default/titlebar/default/minimize_normal.png"
theme.titlebar_ontop_button_focus_active = "/home/hknhmr/.config/awesome/themes/"
	.. "default/titlebar/default/ontop_focus_active.png"
theme.titlebar_ontop_button_focus_inactive = "/home/hknhmr/.config/awesome/themes/"
	.. "default/titlebar/default/ontop_focus_inactive.png"
theme.titlebar_ontop_button_normal_active = "/home/hknhmr/.config/awesome/themes/"
	.. "default/titlebar/default/ontop_normal_active.png"
theme.titlebar_ontop_button_normal_inactive = "/home/hknhmr/.config/awesome/themes/"
	.. "default/titlebar/default/ontop_normal_inactive.png"
theme.titlebar_sticky_button_focus_active = "/home/hknhmr/.config/awesome/themes/"
	.. "default/titlebar/default/sticky_focus_active.png"
theme.titlebar_sticky_button_focus_inactive = "/home/hknhmr/.config/awesome/themes/"
	.. "default/titlebar/default/sticky_focus_inactive.png"
theme.titlebar_sticky_button_normal_active = "/home/hknhmr/.config/awesome/themes/"
	.. "default/titlebar/default/sticky_normal_active.png"
theme.titlebar_sticky_button_normal_inactive = "/home/hknhmr/.config/awesome/themes/"
	.. "default/titlebar/default/sticky_normal_inactive.png"

theme.wallpaper = "~/Downloads/Metal Gear Art.png"

-- You can use your own layout icons like this:
theme.layout_fairh = themes_path .. "default/layouts/fairhw.png"
theme.layout_fairv = themes_path .. "default/layouts/fairvw.png"
theme.layout_floating = themes_path .. "default/layouts/floatingw.png"
theme.layout_magnifier = themes_path .. "default/layouts/magnifierw.png"
theme.layout_max = themes_path .. "default/layouts/maxw.png"
theme.layout_fullscreen = themes_path .. "default/layouts/fullscreenw.png"
theme.layout_tilebottom = themes_path .. "default/layouts/tilebottomw.png"
theme.layout_tileleft = themes_path .. "default/layouts/tileleftw.png"
theme.layout_tile = themes_path .. "default/layouts/tilew.png"
theme.layout_tiletop = themes_path .. "default/layouts/tiletopw.png"
theme.layout_spiral = themes_path .. "default/layouts/spiralw.png"
theme.layout_dwindle = themes_path .. "default/layouts/dwindlew.png"
theme.layout_cornernw = themes_path .. "default/layouts/cornernww.png"
theme.layout_cornerne = themes_path .. "default/layouts/cornernew.png"
theme.layout_cornersw = themes_path .. "default/layouts/cornersww.png"
theme.layout_cornerse = themes_path .. "default/layouts/cornersew.png"

-- Generate Awesome icon:
theme.awesome_icon = theme_assets.awesome_icon(theme.menu_height, theme.bg_focus, theme.fg_focus)

-- Define the icon theme for application icons. If not set then the icons
-- from /usr/share/icons and /usr/share/icons/hicolor will be used.
theme.icon_theme = nil

theme.tasklist_sticky             = "<b>STICKY</b> "  -- Custom sticky icon
theme.tasklist_ontop              = "<b>ONTOP</b> "   -- Custom ontop icon
theme.tasklist_above              = "<b>ABOVE</b> "   -- Custom above icon
theme.tasklist_below              = "<b>BELOW</b> "   -- Custom below icon
theme.tasklist_floating           = "<b>FLOAT</b> "   -- Custom floating icon
theme.tasklist_maximized          = "<b>MAX</b> "   -- Custom maximized icon


theme.systray_icon_spacing = dpi(10)

return theme
