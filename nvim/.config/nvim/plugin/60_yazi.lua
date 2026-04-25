local later = Config.later

later(function()
	vim.pack.add({ "https://github.com/mikavilpas/yazi.nvim" })
	vim.pack.add({ "https://github.com/nvim-lua/plenary.nvim" })
	local opts = {
		open_for_directories = true,
		keymaps = {
			show_help = "<f1>",
			open_file_in_vertical_split = "<c-v>",
			open_file_in_horizontal_split = "<c-x>",
			open_file_in_tab = "<c-t>",
			grep_in_directory = "<c-s>",
			replace_in_directory = "<c-g>",
			cycle_open_buffers = "<tab>",
			copy_relative_path_to_selected_files = "<c-y>",
			send_to_quickfix_list = "<c-q>",
			change_working_directory = "<c-/>",
			open_and_pick_window = "<c-o>",
		},
		floating_window_scaling_factor = 1.00,
		yazi_floating_window_border = "none",
	}
	require("yazi").setup(opts)
end)
