local later = Config.later

later(function()
	vim.pack.add({ 'https://github.com/ibhagwan/fzf-lua' })
	require("fzf-lua").setup({

		fzf_bin = "fzf",
		fzf_opts = {
			["--tmux"] = "center,85%,80%,border-native",
			["--info"] = "inline-right",
			["--separator"] = "+-",
			["--preview-window"] = "right:80%",
			["--preview-border"] = "line",

			["--bind"] =
				"f5:change-preview-window(" ..
				"right,80%,border-left|" ..
				"down,70%,border-top|" ..
				"left,80%,border-right|" ..
				"up,90%,border-bottom|" ..
				"hidden" ..
				")",
		},
		fzf_colors = true,

		winopts = {
			preview = {
				hidden = false,
				horizontal = "right:70%",
				layout = "horizontal",
				default = "bat",
				border = "border-line",
			}
		},
		previewers = {
			bat = { args = "--color=always --style=full" },
			bat_native = { args = "--color=always --style=full" },
		},
		keymap = {
			fzf = {
				true, -- inherit all defaults
				["ctrl-f"] = "forward-char",
				["ctrl-b"] = "backward-char",
				["ctrl-a"] = "beginning-of-line",
				["ctrl-e"] = "end-of-line",
			},
		},

	})
end)
