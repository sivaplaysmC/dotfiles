local keymap = vim.keymap.set

keymap("i", "<C-S-v>", "<C-r><C-o>*", { desc = "Paste from System in Insertmode" })

local start_replace = function()
	local word = vim.fn.expand("<cword>")
	local cmd = ":%s/" .. word .. "/"
	vim.api.nvim_feedkeys(cmd, "n", false)
end
keymap("n", "<leader>rw", start_replace, { desc = "Start Replace" })

keymap("n", "<leader>bd", "<cmd>bd<cr>", { desc = "Close Buffer" })
keymap("n", "<leader>`", "<C-^>", { desc = "Alternate buffers" })

keymap("n", "<leader>cf", require("conform").format, { desc = "Format Buffer" })

-- keymap("", "<C-q>", "<cmd>copen<cr>", { desc = "close quickfix list" })


