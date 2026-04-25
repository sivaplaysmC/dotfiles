-- ~/.config/nvim/ftplugin/go.lua

-- Use conform explicitly for this buffer
vim.b.conform_formatters = { "goimports", "gofmt" }

-- Optional: Go-specific settings
vim.bo.expandtab = false
vim.bo.shiftwidth = 4
vim.bo.tabstop = 4
