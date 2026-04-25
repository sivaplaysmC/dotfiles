vim.o.nu = true
vim.o.rnu = true
vim.o.tabstop = 4
vim.g.mapleader = " "
vim.o.laststatus = 2
vim.o.list = true
vim.o.listchars = table.concat({ "extends:…", "nbsp:␣", "precedes:…", "tab:> " }, ",")
vim.o.autoindent = true
vim.o.shiftwidth = 4
vim.o.scrolloff = 10
vim.o.tgc = true
vim.o.updatetime = 1000
vim.o.spelllang = "en"
vim.o.signcolumn = "yes:2"
vim.o.showtabline = 1
vim.o.ignorecase = true
vim.o.smartcase = true
vim.o.undofile = true
vim.o.wrap = false
vim.o.colorcolumn = "80"
vim.o.cursorline = true
vim.o.cursorcolumn = true
vim.o.splitright = true
vim.o.splitbelow = true

vim.opt.iskeyword:append("-")
-- don't save blank buffers to sessions (like neo-tree, trouble etc.)
vim.opt.sessionoptions:remove("blank")

vim.api.nvim_create_autocmd("TextYankPost", {
	callback = function()
		vim.hl.on_yank { higroup = 'Visual', timeout = 300 }
	end
})

local h = vim.api.nvim_set_hl
vim.cmd([[hi Normal guibg=None]])
h(0, "TabLineSel", {
	bold = true,
	italic = false,
	background = "NvimDarkGrey4",
})

h(0, "@markup.strong", { bold = true })
h(0, "@markup.italic", { italic = true })
h(0, "@markup.strikethrough", { strikethrough = true })
h(0, "@markup.underline", { underline = true })

h(0, "@markup.heading.1", { link = "markdownH1" })
h(0, "@markup.heading.2", { link = "markdownH2" })
h(0, "@markup.heading.3", { link = "markdownH3" })
h(0, "@markup.heading.4", { link = "markdownH4" })
h(0, "@markup.heading.5", { link = "markdownH5" })
h(0, "@markup.heading.6", { link = "markdownH6" })

h(0, "MiniStatuslineModeNormal", { link = "DiffAdd" })
