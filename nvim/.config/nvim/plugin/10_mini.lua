local now, now_if_no_args, later, on_event = Config.now, Config.now_if_no_args, Config.later, Config.on_event

MiniIcons = require("mini.icons")
MiniIcons.setup({ style = "ascii" })
later(MiniIcons.mock_nvim_web_devicons)
later(MiniIcons.tweak_lsp_kind)

now_if_no_args(function()
	MiniStarter = require("mini.starter")

	local header = [[
⣿⣿⣿⣿⣿⣿⣿⣿⡿⣿⣿⣿⣿⣿⡿⢿⡿⠃⠀⡐⠀⠘⡻⠿⠋⠛⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⡏⠈⣤⡝⠛⢻⣷⡆⠀⠀⠀⠀⠀⣤⣧⠀⠀⠀⠀⠚⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⡇⡀⠀⢴⣮⡀⠉⠁⠀⠀⠀⠀⠁⣹⠛⠋⠉⣰⢄⣠⣿⣿⣿⣿⣿⡿⡿⠿⢿⡿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⡿⠿⢇⣗⠀⢈⠙⣷⠀⡐⢀⠀⡀⠀⢀⣴⣦⡄⢂⢀⣺⣿⣿⣿⣿⠏⠁⣠⣤⣤⣤⣭⣕⡲⣌⡋⠻⠿⠿⠿⠛⠛⣛
⣿⣿⣿⣿⣿⣇⠀⠀⠀⠀⠾⢯⡙⢇⠀⢃⢀⣀⠢⡿⠋⢐⠶⠇⣿⣿⣿⣿⠟⠁⣺⣿⣿⣿⣿⣿⣿⣿⣷⣵⡛⣃⣀⣠⣀⣠⣾⣿
⣿⣿⣿⣿⣿⣷⠀⠀⢸⣦⠀⠀⠉⠂⠁⢆⣌⠆⡆⢷⡍⠹⠷⠸⠿⠿⠏⠁⣤⡌⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣆⠀⠀⠻⣷⣦⡀⠀⢠⠂⢾⠀⠀⠀⠀⢀⠂⠀⣤⣶⣾⣿⣿⣿⣶⣤⣤⣤⣨⡙⢿⣿⣿⣿⣿⣿⢿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⠟⠁⠀⠀⠀⠚⠋⢠⣾⣿⡼⣹⣮⣤⣰⡶⠏⠀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⣼⣿⣻⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⡿⢡⣏⡇⠀⠀⠀⢀⢰⣰⢿⡛⠣⠆⢿⣿⣿⠇⠀⠀⠈⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⡇⣸⡇⠿⠀⠀⠀⡀⠸⡀⠘⠃⠀⠀⢾⢿⠇⠀⠀⠀⢀⢰⠘⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⢃⣿⡻⡀⣣⠀⠀⠀⠂⠁⠈⠈⠀⠘⠀⠄⣽⠐⠃⠀⠈⡈⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⠸⣿⣷⢄⠀⠱⡄⠀⠀⠀⢿⣷⣷⠀⠔⠈⠁⠀⠀⠀⣘⠁⠘⠻⠿⠿⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⠋⠴⣬⣨⠣⣾⣷⣥⡽⠆⠀⠀⠁⠉⠀⠀⠀⠀⢀⠀⠀⣼⠁⠀⢀⣄⡦⠭⠤⠶⠤⣬⣍⣻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣧⣤⣿⡟⢄⡙⠛⠉⠁⢃⠐⠀⠀⠀⠀⠀⠜⠀⠈⣀⡿⠋⠀⣸⡿⠛⠁⠀⠀⠘⠀⢉⠉⠹⢿⢟⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⡿⣿⣿⣿⣎⠀⠀⠀⠀⠘⠀⠁⠀⠀⠀⠀⠀⠀⠀⠟⠑⠀⠀⠈⠀⠀⠀⠀⠠⢤⠤⣨⣷⡀⠀⣚⡋⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
]]
	local footer = [[
Loaded %s plugins.
Why are we still here, Just to suffer?!
]]
	footer = string.format(footer, #vim.pack.get(nil, { info = false }))

	MiniStarter.setup({
		header = header,
		footer = footer,
		items = {
			MiniStarter.sections.recent_files(10, true),
		},

		content_hooks = {
			MiniStarter.gen_hook.adding_bullet(),
			MiniStarter.gen_hook.aligning("center", "center"),
		},
	})
end)


later(function()
	require("mini.ai").setup({})
end)

later(function()
	require("mini.bracketed").setup()
end)
later(function()
	require("mini.bufremove").setup()
end)

later(function()
	local miniclue = require("mini.clue")
	-- stylua: ignore
	miniclue.setup({
		-- Define which clues to show. By default shows only clues for custom mappings
		-- (uses `desc` field from the mapping; takes precedence over custom clue).
		clues = {
			-- This is defined in 'plugin/20_keymaps.lua' with Leader group descriptions
			Config.leader_group_clues,
			miniclue.gen_clues.builtin_completion(),
			miniclue.gen_clues.g(),
			miniclue.gen_clues.marks(),
			miniclue.gen_clues.registers(),
			miniclue.gen_clues.square_brackets(),
			-- This creates a submode for window resize mappings. Try the following:
			-- - Press `<C-w>s` to make a window split.
			-- - Press `<C-w>+` to increase height. Clue window still shows clues as if
			--   `<C-w>` is pressed again. Keep pressing just `+` to increase height.
			--   Try pressing `-` to decrease height.
			-- - Stop submode either by `<Esc>` or by any key that is not in submode.
			miniclue.gen_clues.z(),
		},
		-- Explicitly opt-in for set of common keys to trigger clue window
		triggers = {
			{ mode = { 'n', 'x' }, keys = '<Leader>' }, -- Leader triggers
			{ mode = 'n',          keys = '\\' }, -- mini.basics
			{ mode = { 'n', 'x' }, keys = '[' }, -- mini.bracketed
			{ mode = { 'n', 'x' }, keys = ']' },
			{ mode = 'i',          keys = '<C-x>' }, -- Built-in completion
			{ mode = { 'n', 'x' }, keys = 'g' }, -- `g` key
			{ mode = { 'n', 'x' }, keys = "'" }, -- Marks
			{ mode = { 'n', 'x' }, keys = '`' },
			{ mode = { 'n', 'x' }, keys = '"' }, -- Registers
			{ mode = { 'i', 'c' }, keys = '<C-r>' },
			{ mode = 'n',          keys = '<C-w>' }, -- Window commands
			{ mode = { 'n', 'x' }, keys = 's' }, -- `s` key (mini.surround, etc.)
			{ mode = { 'n', 'x' }, keys = 'z' }, -- `z` key
		},
		window = {
			delay = 100,
		}
	})
end)

later(function()
	local config = {
		-- Options for how hunks are visualized
		view = {
			-- Visualization style. Possible values are 'sign' and 'number'.
			-- Default: 'number' if line numbers are enabled, 'sign' otherwise.
			style = "sign",

			-- Signs used for hunks with 'sign' view
			signs = { add = "+", change = "~", delete = "-" },

			-- Priority of used visualization extmarks
			priority = 199,
		},

		-- Source(s) for how reference text is computed/updated/etc
		-- Uses content from Git index by default
		source = nil,

		-- Delays (in ms) defining asynchronous processes
		delay = {
			-- How much to wait before update following every text change
			text_change = 200,
		},

		-- Module mappings. Use `''` (empty string) to disable one.
		mappings = {
			-- Apply hunks inside a visual/operator region
			apply = "gh",

			-- Reset hunks inside a visual/operator region
			reset = "gH",

			-- Hunk range textobject to be used inside operator
			-- Works also in Visual mode if mapping differs from apply and reset
			textobject = "gh",

			-- Go to hunk range in corresponding direction
			goto_first = "[H",
			goto_prev = "[h",
			goto_next = "]h",
			goto_last = "]H",
		},

		-- Various options
		options = {
			-- Diff algorithm. See `:h vim.diff()`.
			algorithm = "histogram",

			-- Whether to use "indent heuristic". See `:h vim.diff()`.
			indent_heuristic = true,

			-- The amount of second-stage diff to align lines
			linematch = 60,

			-- Whether to wrap around edges during hunk navigation
			wrap_goto = false,
		},
	}

	require("mini.diff").setup(config)
end)
later(function()
	require("mini.git").setup()
end)
later(function()
	require("mini.indentscope").setup()
end)

later(function()
	require("mini.pairs").setup({ modes = { command = true } })
end)

later(function()
	require("mini.surround").setup({
		-- Add custom surroundings to be used on top of builtin ones. For more
		-- information with examples, see `:h MiniSurround.config`.
		custom_surroundings = nil,

		-- Duration (in ms) of highlight when calling `MiniSurround.highlight()`
		highlight_duration = 500,

		-- Module mappings. Use `''` (empty string) to disable one.
		mappings = {
			add = "ys",   -- Add surrounding (Normal and Visual mode: ysiw], yssb, etc.)
			delete = "ds", -- Delete surrounding (ds", ds{, etc.)
			replace = "cs", -- Change/replace surrounding (cs"' , cs'<q>, etc.)
			find = "sf",  -- Find surrounding to the right (not in original examples)
			find_left = "sF", -- Find surrounding to the left
			highlight = "sh", -- Highlight surrounding
			update_n_lines = "sn", -- Update `n_lines`
			suffix_last = "l", -- Suffix for search with "prev" method
			suffix_next = "n", -- Suffix for search with "next" method
		},

		-- Number of lines within which surrounding is searched
		n_lines = 200,

		-- Whether to respect selection type:
		-- - Place surroundings on separate lines in linewise mode.
		-- - Place surroundings on each line in blockwise mode.
		respect_selection_type = false,

		-- How to search for surrounding (first inside current line, then inside
		-- neighborhood). One of 'cover', 'cover_or_next', 'cover_or_prev',
		-- 'cover_or_nearest', 'next', 'prev', 'nearest'. For more details,
		-- see `:h MiniSurround.config`.
		search_method = "cover",

		-- Whether to disable showing non-error feedback
		-- This also affects (purely informational) helper messages shown after
		-- idle time if user input is required.
		silent = false,
	})
end)

later(function()
	require("mini.trailspace").setup()
end)
