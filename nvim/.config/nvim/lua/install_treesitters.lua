return function()
	require('nvim-treesitter').
		install(_G.ts_types)
		:wait(300000)
end
