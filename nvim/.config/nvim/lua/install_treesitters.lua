return function()
	vim.cmd("packadd nvim-treesitter")
	require('nvim-treesitter').
		install(_G.ts_types)
		:wait(300000)
end
