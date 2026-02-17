-- mini setup
local path_package = vim.fn.stdpath("data") .. "/site/"
local mini_path = path_package .. "pack/deps/start/mini.nvim"
if not vim.uv.fs_stat(mini_path) then
	vim.cmd('echo "Installing `mini.nvim`" | redraw')
	local clone_cmd = {
		"git",
		"clone",
		"--filter=blob:none",
		"https://github.com/echasnovski/mini.nvim",
		mini_path,
	}
	vim.fn.system(clone_cmd)
	vim.cmd("packadd mini.nvim | helptags ALL")
	vim.cmd('echo "Installed `mini.nvim`" | redraw')
end

-- mini.deps base setup
require("mini.deps").setup({ path = { package = path_package } })

local add, now, later = MiniDeps.add, MiniDeps.now, MiniDeps.later

add("ibhagwan/fzf-lua")
add("mikavilpas/yazi.nvim")
add("nvim-lua/plenary.nvim")
add("stevearc/conform.nvim")
add("nvim-treesitter/nvim-treesitter")
add({
	source = "saghen/blink.cmp",
	depends = { "rafamadriz/friendly-snippets" },
	checkout = "v1.6.0", -- check releases for latest tag
})
add("j-hui/fidget.nvim")
add("hxueh/beancount.nvim")

-- Neovim Options
now(function()
	vim.g.loaded_node_provider = 0
	vim.g.loaded_perl_provider = 0
	vim.g.loaded_ruby_provider = 0
	vim.g.loaded_python_provider = 0
	vim.g.loaded_python3_provider = 0

	vim.g.mapleader = " "
	vim.o.number = true
	vim.o.relativenumber = true
	vim.o.laststatus = 2
	vim.o.list = true
	vim.o.listchars = table.concat({ "extends:…", "nbsp:␣", "precedes:…", "tab:> " }, ",")
	vim.o.autoindent = true
	vim.o.shiftwidth = 4
	vim.o.tabstop = 4
	vim.o.expandtab = true
	vim.o.scrolloff = 10
	vim.o.tgc = true
	-- vim.o.clipboard = "unnamed,unnamedplus"
	vim.o.updatetime = 1000
	vim.opt.iskeyword:append("-")
	vim.o.spelllang = "de,en"
	vim.o.spelloptions = "camel"
	vim.opt.complete:append("kspell")
	vim.o.path = vim.o.path .. ",**"
	vim.o.tags = vim.o.tags .. ",/home/dosa/.config/nvim/tags"
	-- don't save blank buffers to sessions (like neo-tree, trouble etc.)
	vim.opt.sessionoptions:remove("blank")
	vim.cmd([[set rnu]])
	vim.cmd([[set nu]])
end)

later(require("mini.align").setup)
later(require("mini.bracketed").setup)
later(require("mini.doc").setup)
later(require("mini.extra").setup)
later(require("mini.git").setup)
later(require("mini.icons").setup)
later(require("mini.jump").setup)
later(require("mini.misc").setup)
later(require("mini.bufremove").setup)
later(require("mini.comment").setup)
later(require("mini.operators").setup)
later(require("mini.pairs").setup)
later(require("mini.splitjoin").setup)
later(require("mini.tabline").setup)
later(require("mini.trailspace").setup)
later(require("mini.visits").setup)
later(require("fidget").setup)
later(require("mini.align").setup)
later(require("mini.bracketed").setup)
later(require("mini.doc").setup)
later(require("mini.extra").setup)
later(require("mini.git").setup)
later(require("mini.icons").setup)
later(require("mini.jump").setup)
later(require("mini.misc").setup)
later(require("mini.bufremove").setup)
later(require("mini.comment").setup)
later(require("mini.operators").setup)
later(require("mini.pairs").setup)
later(require("mini.splitjoin").setup)
later(require("mini.tabline").setup)
later(require("mini.trailspace").setup)
later(require("mini.visits").setup)
later(require("fidget").setup)

later(function()
	require("mini.basics").setup({
		options = {
			basic = true,
			extra_ui = true,
			win_borders = "bold",
		},
		mappings = {
			basic = true,
		},
		autocommands = {
			basic = true,
			relnum_in_visual_mode = false,
		},
	})
end)
later(function()
	require("mini.clue").setup({
		triggers = {
			-- Leader triggers
			{ mode = "n", keys = "<Leader>" },
			{ mode = "x", keys = "<Leader>" },

			{ mode = "n", keys = "\\" },

			-- Built-in completion
			{ mode = "i", keys = "<C-x>" },

			-- `g` key
			{ mode = "n", keys = "g" },
			{ mode = "x", keys = "g" },

			-- Surround
			{ mode = "n", keys = "s" },

			-- Marks
			{ mode = "n", keys = "'" },
			{ mode = "n", keys = "`" },
			{ mode = "x", keys = "'" },
			{ mode = "x", keys = "`" },

			-- Registers
			{ mode = "n", keys = '"' },
			{ mode = "x", keys = '"' },
			{ mode = "i", keys = "<C-r>" },
			{ mode = "c", keys = "<C-r>" },

			-- Window commands
			{ mode = "n", keys = "<C-w>" },

			-- `z` key
			{ mode = "n", keys = "z" },
			{ mode = "x", keys = "z" },
		},

		clues = {
			{ mode = "n", keys = "<Leader>b", desc = " Buffer" },
			{ mode = "n", keys = "<Leader>g", desc = "󰊢 Git" },
			require("mini.clue").gen_clues.g(),
			require("mini.clue").gen_clues.builtin_completion(),
			require("mini.clue").gen_clues.marks(),
			require("mini.clue").gen_clues.registers(),
			require("mini.clue").gen_clues.windows(),
			require("mini.clue").gen_clues.z(),
		},
		window = {
			delay = 300,
			config = {
				width = 50,
				border = "single",
			},
		},
	})
end)

later(function()
	local opts = {
		keymap = { preset = "default" },
		appearance = {
			nerd_font_variant = "propo",
		},

		completion = { documentation = { auto_show = true } },
		sources = {
			default = { "lsp", "path", "snippets", "buffer" },
		},
		fuzzy = { implementation = "prefer_rust_with_warning" },
	}

	require("blink.cmp").setup(opts)
end)

later(function()
	require("mini.cursorword").setup()
	vim.api.nvim_set_hl(0, "MiniCursorword", { underline = true })
	vim.api.nvim_set_hl(0, "MiniCursorwordCurrent", { underline = false, bg = NONE })
end)
later(function()
	require("mini.diff").setup({
		view = {
			style = "sign",
			signs = { add = "+", change = "-", delete = "~" },
		},
	})
end)

later(function()
	require("mini.move").setup({
		mappings = {
			-- Move visual selection in Visual mode. Defaults are Alt (Meta) + hjkl.
			left = "<M-S-h>",
			right = "<M-S-l>",
			down = "<M-S-j>",
			up = "<M-S-k>",

			-- Move current line in Normal mode
			line_left = "<M-S-h>",
			line_right = "<M-S-l>",
			line_down = "<M-S-j>",
			line_up = "<M-S-k>",
		},
	})
end)
later(function()
	-- We took this from echasnovski's personal configuration
	-- https://github.com/echasnovski/nvim/blob/master/init.lua

	local filterout_lua_diagnosing = function(notif_arr)
		local not_diagnosing = function(notif)
			return not vim.startswith(notif.msg, "lua_ls: Diagnosing")
		end
		notif_arr = vim.tbl_filter(not_diagnosing, notif_arr)
		return MiniNotify.default_sort(notif_arr)
	end
	require("mini.notify").setup({
		content = { sort = filterout_lua_diagnosing },
		lsp_progress = { enable = false },
		window = { config = { border = "solid" } },
	})
	vim.notify = MiniNotify.make_notify()
end)

later(function()
	local win_config = function()
		local height = math.floor(0.618 * vim.o.lines)
		local width = math.floor(0.4 * vim.o.columns)
		return {
			anchor = "NW",
			height = height,
			width = width,
			border = "solid",
			row = math.floor(0.5 * (vim.o.lines - height)),
			col = math.floor(0.5 * (vim.o.columns - width)),
		}
	end
	require("mini.pick").setup({
		mappings = {
			choose_in_vsplit = "<C-CR>",
		},
		options = {
			use_cache = true,
		},
		window = {
			config = win_config,
		},
	})
	vim.ui.select = MiniPick.ui_select
end)

later(function()
	local gen_loader = require("mini.snippets").gen_loader
	require("mini.snippets").setup({
		snippets = {
			-- Load custom file with global snippets first (adjust for Windows)
			gen_loader.from_file("~/.config/nvim/snippets/global.json"),

			-- Load snippets based on current language by reading files from
			-- "snippets/" subdirectories from 'runtimepath' directories.
			gen_loader.from_lang(),
		},
	})
end)
later(function()
	require("mini.statusline").setup({
		content = {
			active = function()
				local mode, mode_hl = MiniStatusline.section_mode({ trunc_width = 120 })
				local git = MiniStatusline.section_git({ trunc_width = 40 })
				local filename = MiniStatusline.section_filename({ trunc_width = 140 })
				local fileinfo = MiniStatusline.section_fileinfo({ trunc_width = 120 })
				local search = MiniStatusline.section_searchcount({ trunc_width = 75 })

				return MiniStatusline.combine_groups({
					{ hl = mode_hl, strings = { mode } },
					{ hl = "MiniStatuslineDevinfo", strings = { git, diff, diagnostics, lsp } },
					"%<", -- Mark general truncate point
					{ hl = "MiniStatuslineFilename", strings = { filename } },
					"%=", -- End left alignment
					{ hl = "MiniStatuslineFileinfo", strings = { fileinfo } },
					{ hl = mode_hl, strings = { search, location } },
				})
			end,
			inactive = nil,
		},
	})
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
			add = "ys", -- Add surrounding (Normal and Visual mode: ysiw], yssb, etc.)
			delete = "ds", -- Delete surrounding (ds", ds{, etc.)
			replace = "cs", -- Change/replace surrounding (cs"' , cs'<q>, etc.)
			find = "sf", -- Find surrounding to the right (not in original examples)
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
	require("fzf-lua").setup({

		-- fzf_bin = "fzf-tmux",
		fzf_opts = {
			["--tmux"] = "center,80%,70%,border-native",
			["--info"] = "inline-right",
			["--separator"] = "+-",
			["--preview-border"] = "line",
		},

		fzf_colors = false,
	})
end)

later(function()
	---@type YaziConfig
	local opts = {
		open_for_directories = true,
		keymaps = {
			show_help = "<f1>",
		},
		floating_window_scaling_factor = 1.00,
		yazi_floating_window_border = "none",
	}
	require("yazi").setup(opts)
	vim.keymap.set("n", "<leader>;", "<cmd>Yazi<cr>", nil)
end)

later(function()
	local fzf = require("fzf-lua")

	local commands = function()
		fzf.commands({})
	end

	local nvim_conf = function()
		fzf.files({
			cwd = vim.fn.stdpath("config"),
			prompt = "Neovim Config Files> ",
			cwd_prompt = false,
		})
	end

	local files = function()
		return fzf.files({
			fzf_opts = {
				["--bind"] = "ctrl-y:execute(foot)",
			},
			keymap = {
				fzf = {
					["ctrl-y"] = "execute-silent(echo -n {} | sed 's/^[^[:alnum:].]*//' | wl-copy)",
				},
			},
		})
	end

	local cur_buffer_search = function()
		fzf.live_grep({
			grep_opts = "--files-with-matches",
			prompt = "Live Grep in Open Files> ",
		})
	end

	vim.keymap.set("n", "<M-;>", commands, { desc = "[S]earch [C]ommands" })

	vim.keymap.set("n", "<leader>sh", fzf.helptags, { desc = "[S]earch [H]elp" })
	vim.keymap.set("n", "<leader>sk", fzf.keymaps, { desc = "[S]earch [K]eymaps" })
	vim.keymap.set("n", "<leader>sf", files, { desc = "[S]earch [F]iles" })
	vim.keymap.set("n", "<leader>ss", fzf.builtin, { desc = "[S]earch [S]elect FZF-Lua" })

	vim.keymap.set("n", "<leader>sw", fzf.grep_cword, { desc = "[S]earch current [W]ord" })
	vim.keymap.set("n", "<leader>sg", fzf.live_grep, { desc = "[S]earch by [G]rep" })
	vim.keymap.set("n", "<leader>sd", fzf.diagnostics_document, { desc = "[S]earch [D]iagnostics" })
	vim.keymap.set("n", "<leader>sD", fzf.diagnostics_workspace, { desc = "[S]earch [D]iagnostics (Workspace)" })
	vim.keymap.set("n", "<leader>sr", fzf.resume, { desc = "[S]earch [R]esume" })
	vim.keymap.set("n", "<leader>s.", fzf.oldfiles, { desc = '[S]earch Recent Files ("." for repeat)' })
	vim.keymap.set("n", "<leader><leader>", fzf.buffers, { desc = "[ ] Find existing buffers" })

	fzf.register_ui_select()

	vim.keymap.set("n", "<leader>/", fzf.blines, { desc = "[/] Fuzzily search in current buffer" })
	vim.keymap.set("n", "<leader>s/", cur_buffer_search, { desc = "[S]earch [/] in Open Files" })
	vim.keymap.set("n", "<leader>sn", nvim_conf, { desc = "[S]earch [N]eovim files" })
	vim.keymap.set("n", "<leader>'", require("conform").format, { desc = "format with conform" })
end)

require("autocmds")
require("filetypes")
require("highlights")
require("keybinds")

local uv = vim.loop
local json = vim.json

local trust_file = vim.fn.stdpath("data") .. "/trusted_nvim.json"

--- Load the trust DB from disk
local function load_trust_db()
	local f = io.open(trust_file, "r")
	if not f then
		return {}
	end
	local ok, data = pcall(json.decode, f:read("*a"))
	f:close()
	return ok and data or {}
end

--- Save trust DB to disk
local function save_trust_db(db)
	local f = assert(io.open(trust_file, "w"))
	f:write(json.encode(db))
	f:close()
end

--- Recursively compute hash of all files in dir
local function hash_dir(path)
	local sha256 = vim.fn.sha256 or function(s)
		return vim.fn.sha256(s) -- fallback
	end

	local handle
	local function scan_dir(dir)
		local list = {}
		handle = uv.fs_scandir(dir)
		if not handle then
			return ""
		end

		while true do
			local name, type = uv.fs_scandir_next(handle)
			if not name then
				break
			end
			local fullpath = dir .. "/" .. name
			if type == "file" then
				local fd = io.open(fullpath, "rb")
				if fd then
					local content = fd:read("*a")
					fd:close()
					table.insert(list, sha256(content))
				end
			elseif type == "directory" then
				table.insert(list, scan_dir(fullpath))
			end
		end

		return sha256(table.concat(list))
	end

	return scan_dir(path)
end

--- Ask the user if they trust the folder
local function ask_trust(path, hash)
	local answer = vim.fn.input("Trust local config at " .. path .. "? (y/N): ")
	if answer:lower() == "y" then
		local db = load_trust_db()
		db[path] = hash
		save_trust_db(db)
		return true
	end
	return false
end

--- Load per-project config with trust verification
local function load_local_nvim_config()
	local cwd = uv.fs_realpath(uv.cwd())
	if not cwd then
		return
	end

	while cwd do
		local nvim_dir = cwd .. "/.nvim"
		local stat = uv.fs_stat(nvim_dir)
		if stat and stat.type == "directory" then
			local hash = hash_dir(nvim_dir)
			local db = load_trust_db()

			if db[nvim_dir] ~= hash then
				if not ask_trust(nvim_dir, hash) then
					vim.notify("Local config at " .. nvim_dir .. " not trusted, skipping.", vim.log.levels.WARN)
					return
				end
			end

			vim.opt.runtimepath:append(nvim_dir)
			vim.opt.runtimepath:append(nvim_dir .. "/lua/")
			local init_lua = nvim_dir .. "/init.lua"
			if uv.fs_stat(init_lua) then
				dofile(init_lua)
			end
			return
		end

		local parent = cwd:match("(.+)/[^/]+$")
		if parent == cwd then
			break
		end
		cwd = parent
	end
end

-- Run at startup
load_local_nvim_config()

local mygroup = vim.api.nvim_create_augroup("vimrc", { clear = true })
vim.api.nvim_create_autocmd("LspAttach", {
	group = mygroup,
	callback = function(ev)
		local opts = {
			buffer = ev.buf,
		}
		vim.keymap.set("n", "grn", vim.lsp.buf.rename, opts)
		vim.keymap.set("n", "gra", vim.lsp.buf.code_action, opts)
		vim.keymap.set("n", "grr", vim.lsp.buf.references, opts)
		vim.keymap.set("n", "gri", vim.lsp.buf.implementation, opts)
		vim.keymap.set("n", "gD", vim.lsp.buf.type_definition, opts)
		vim.keymap.set("n", "gd", vim.lsp.buf.definition, opts)
		vim.keymap.set("n", "g<C-d>", vim.lsp.buf.declaration, opts)
		vim.keymap.set("i", "<C-s>", vim.lsp.buf.signature_help, opts)
	end,
})

later(function()
	local filetypes =
		{ "bash", "c", "diff", "html", "lua", "luadoc", "markdown", "markdown_inline", "query", "vim", "vimdoc" }
	-- require("nvim-treesitter").install(filetypes)
	vim.api.nvim_create_autocmd("FileType", {
		pattern = filetypes,
		callback = function()
			vim.treesitter.start()
		end,
	})
end)

later(function()
	local enabled_langservers = {
		"lua-language-server",
		"gopls",
		"clangd",
		"ty",
		"rust_analyzer",
		"zls",
		"tinymist",
		"vtsls",
	}

	for _, langserver in ipairs(enabled_langservers) do
		vim.lsp.enable(langserver)
	end
end)

later(function()
	require("conform").setup({
		formatters_by_ft = {
			lua = { "stylua" },
			-- Conform will run multiple formatters sequentially
			go = { "goimports", "gofmt" },
			-- You can also customize some of the format options for the filetype
			rust = { "rustfmt", lsp_format = "fallback" },
			-- You can use a function here to determine the formatters dynamically
			python = function(bufnr)
				if require("conform").get_formatter_info("ruff_format", bufnr).available then
					return { "ruff_format" }
				else
					return { "isort", "black" }
				end
			end,
			c = { "clang-format" },
			typescriptreact = { "prettier" },
			javascript = { "prettier" },
			zig = { lsp_format = "prefer" },
			-- Use the "*" filetype to run formatters on all filetypes.
			["*"] = { "codespell" },
			-- Use the "_" filetype to run formatters on filetypes that don't
			-- have other formatters configured.
			["_"] = { "trim_whitespace" },
		},
	})
	vim.keymap.set("n", "<leader>'", require("conform").format, { desc = "format buffer" })
end)

now(function()
	vim.cmd([[hi Normal guibg=None]])
end)

later(function()
	require("beancount").setup({
		-- Alignment & formatting
		separator_column = 70, -- Column for decimal separator alignment
		instant_alignment = true, -- Align amounts on decimal point entry
		fixed_cjk_width = false, -- Treat CJK characters as 2-width
		auto_format_on_save = true, -- Auto formatting file on saving
		auto_fill_amounts = false, -- Auto-fill missing amounts on save (opt-in)

		-- Completion & input
		complete_payee_narration = true, -- Include payees/narrations

		-- Files & paths
		python_path = "/home/hknhmr/.local/share/pipx/venvs/beancount/bin/python3", -- Python executable path

		-- Diagnostics & warnings
		flag_warnings = { -- Transaction flag warning levels
			["*"] = nil, -- FLAG_OKAY - Transactions that have been checked
			["!"] = vim.diagnostic.severity.WARN, -- FLAG_WARNING - Mark by user as something to be looked at later
			["P"] = nil, -- FLAG_PADDING - Transactions created from padding directives
			["S"] = nil, -- FLAG_SUMMARIZE - Transactions created due to summarization
			["T"] = nil, -- FLAG_TRANSFER - Transactions created due to balance transfers
			["C"] = nil, -- FLAG_CONVERSIONS - Transactions created to account for price conversions
			["M"] = nil, -- FLAG_MERGING - A flag to mark postings merging together legs for average cost
		},
		auto_save_before_check = true, -- Auto-save before diagnostics

		-- Features
		inlay_hints = true, -- Show inferred amounts
		snippets = {
			enabled = true, -- Enable snippet support
			date_format = "%Y-%m-%d", -- Date format for snippets
		},

		-- Key mappings (customizable)
		keymaps = {
			goto_definition = "gd", -- Go to definition
			next_transaction = "]]", -- Next transaction
			prev_transaction = "[[", -- Previous transaction
		},

		-- UI settings
		ui = {
			virtual_text = true, -- Show diagnostics as virtual text
			signs = true, -- Show diagnostic signs
			update_in_insert = false, -- Don't update while typing
			severity_sort = true, -- Sort by severity
		},
	})
end)

function Paste_to_repl(text)
	local pane = vim.fn.system("tmux show -gqv @repl_pane"):gsub("%s+", "")
	if pane == "" then
		print("No REPL pane set")
		return
	end

	-- load buffer
	vim.fn.system({ "tmux", "load-buffer", "-" }, text)
	-- paste (tmux handles bracketed paste)
	vim.fn.system({ "tmux", "paste-buffer", "-p", "-t", pane })
	vim.fn.system({ "tmux", "send-keys", "-t", pane, "Enter" })
end

_G.repl_operator = function(type)
	local start_pos, end_pos

	if type == "char" or type == "line" then
		start_pos = vim.fn.getpos("'[")
		end_pos = vim.fn.getpos("']")
	else
		-- visual mode
		start_pos = vim.fn.getpos("'<")
		end_pos = vim.fn.getpos("'>")
	end

	local lines = vim.fn.getline(start_pos[2], end_pos[2])
	if #lines == 0 then
		return
	end

	-- trim for charwise selection
	if type == "char" then
		lines[#lines] = string.sub(lines[#lines], 1, end_pos[3])
		lines[1] = string.sub(lines[1], start_pos[3])
	end

	Paste_to_repl(table.concat(lines, "\n"))
end

vim.keymap.set("n", "<leader>.", function()
	vim.go.operatorfunc = "v:lua.repl_operator"
	return "g@"
end, { expr = true })

vim.keymap.set("v", "<leader>.", function()
	vim.go.operatorfunc = "v:lua.repl_operator"
	vim.cmd("normal! g@")
end)
