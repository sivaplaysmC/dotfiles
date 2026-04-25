local later = Config.later

later(function()
	vim.pack.add({ "https://github.com/stevearc/conform.nvim" })
	Conform = require("conform")
	Conform.setup({
		formatters_by_ft = {
			lua = { lsp_format = "prefer" },
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

	vim.api.nvim_create_user_command("Format", function() Conform.format({}) end, {})
end)
