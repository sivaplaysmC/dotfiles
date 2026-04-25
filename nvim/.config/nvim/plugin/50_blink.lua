local later = Config.later

later(function()
	vim.pack.add({ { src = "https://github.com/Saghen/blink.cmp", version = vim.version.range("*") } })
	local opts = {
		keymap = { preset = "default" },
		appearance = {
			nerd_font_variant = "propo",
		},

		completion = {
			documentation = { auto_show = true },
			menu = {
				draw = {
					components = {
						kind_icon = {
							text = function(ctx)
								local kind_icon, _, _ = require("mini.icons").get("lsp", ctx.kind)
								return kind_icon
							end,
							-- (optional) use highlights from mini.icons
							highlight = function(ctx)
								local _, hl, _ = require("mini.icons").get("lsp", ctx.kind)
								return hl
							end,
						},
						kind = {
							-- (optional) use highlights from mini.icons
							highlight = function(ctx)
								local _, hl, _ = require("mini.icons").get("lsp", ctx.kind)
								return hl
							end,
						},
					},
				},
			},
		},

		sources = {
			default = { "lsp", "path", "snippets", "buffer" },
		},
		fuzzy = {
			prebuilt_binaries = { force_version = "v1.10.2" },
			implementation = "rust",
		},
		signature = { enabled = true },
	}

	require("blink.cmp").setup(opts)
end)
