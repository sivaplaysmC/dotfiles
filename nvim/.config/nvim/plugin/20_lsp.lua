local later = Config.later

later(function()
	local enabled_langservers = {
		"lua-language-server",
		"gopls",
		"clangd",
		"basedpyright",
		"rust_analyzer",
		"zls",
		"tinymist",
		"vtsls",
	}

	for _, langserver in ipairs(enabled_langservers) do
		vim.lsp.enable(langserver)
	end
end)
