-- Automatically Split help Buffers to the right
vim.api.nvim_create_autocmd("FileType", {
    pattern = "help",
    command = "wincmd L",
})

-- Navigate the Quickfix List
vim.api.nvim_create_autocmd("FileType", {
    pattern = "qf",
    callback = function(event)
        local opts = { buffer = event.buf, silent = true }
        vim.keymap.set("n", "<C-j>", "<cmd>cn<CR>zz<cmd>wincmd p<CR>", opts)
        vim.keymap.set("n", "<C-k>", "<cmd>cN<CR>zz<cmd>wincmd p<CR>", opts)
    end,
})
