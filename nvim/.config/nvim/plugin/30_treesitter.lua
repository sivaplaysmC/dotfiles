local now_if_args = Config.now_if_args
local ts_types = {
	"bash",
	"c",
	"diff",
	"html",
	"lua",
	"go",
	"yaml",
	"luadoc",
	"markdown",
	"markdown_inline",
	"query",
	"vim",
	"vimdoc",
	"python",
}
_G.ts_types = ts_types

now_if_args(function()
	vim.pack.add({ 'https://github.com/nvim-treesitter/nvim-treesitter' })
	require('nvim-treesitter').setup {
		install_dir = vim.fn.stdpath('data') .. '/site'
	}
	require('nvim-treesitter').install(ts_types)

	-- Install missing parsers via native vim.treesitter
	for _, lang in ipairs(ts_types) do
		vim.treesitter.language.add(lang)
	end

	vim.api.nvim_create_autocmd("FileType", {
		pattern = ts_types,
		callback = function()
			vim.treesitter.start()
		end,
	})
end)
