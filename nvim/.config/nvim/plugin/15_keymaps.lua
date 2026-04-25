-- An example helper to create a Normal mode mapping
--
local nmap = function(lhs, rhs, desc)
	if desc then

	else
		desc = rhs
	end

	if type(desc) ~= type("") then
		desc = tostring(desc)
	end

	vim.keymap.set('n', lhs, rhs, { desc = desc })
end

-- An example helper to create a Normal mode mapping
local nvoxmap = function(lhs, rhs, desc)
	if desc then
	else
		desc = rhs
	end

	if type(desc) ~= type("") then
		desc = tostring(desc)
	end

	vim.keymap.set({ 'v', 'n', 'x', 'o' }, lhs, rhs, { desc = desc })
end

local nvoxmap_leader = function(suffix, rhs, desc)
	nvoxmap('<Leader>' .. suffix, rhs, desc)
end

local nmap_leader = function(suffix, rhs, desc)
	nmap('<Leader>' .. suffix, rhs, desc)
end

local cmd = function(x)
	return "<cmd>" .. x .. "<cr>"
end

local luacmd = function(x)
	return cmd("lua " .. x)
end

local fzflua = function(x)
	return cmd("FzfLua " .. x)
end

nmap_leader('<leader>', fzflua 'buffers', 'Alternate')
nmap_leader('bd', luacmd("MiniBufremove.delete()"), 'Delete')
nmap_leader('bD', luacmd("MiniBufremove.delete(0, true)"), 'Delete!')

nmap_leader('bw', luacmd("MiniBufremove.wipeout()"), 'Wipeout')
nmap_leader('bW', luacmd("MiniBufremove.wipeout(0, true)"), 'Wipeout!')

nmap_leader('sf', fzflua "files", "search files")
nmap_leader('sn', fzflua('files cwd=' .. vim.fn.stdpath("config")), "search nvim config")
nmap_leader('sh', fzflua "helptags", "search helptags")
nmap_leader('sk', fzflua "keymaps", "search keymaps")
nmap_leader('s:', fzflua "command_history", "search command_history")
nmap_leader('sd', fzflua "lsp_workspace_diagnostics", "search lsp_workspace_diagnostics")
nmap_leader('ss', fzflua "lsp_live_workspace_symbols", "search lsp_live_workspace_symbols")
nmap_leader('sg', fzflua "live_grep", "search live_grep")
nmap_leader('sr', fzflua "resume", "search resume")
nmap_leader('so', fzflua "oldfiles", "search oldfiles")

nmap('gd', vim.lsp.buf.definition, 'Source definition')
nmap('gD', vim.lsp.buf.declaration, 'Source declaration')
nmap('gri', vim.lsp.buf.implementation, 'Implementation')
nmap('grt', vim.lsp.buf.type_definition, 'Type definition')
nmap('grx', vim.lsp.codelens.run, 'Run codelens')
nmap('K', vim.lsp.buf.hover, 'Hover')
nmap('gra', vim.lsp.buf.code_action, 'Actions')
nmap('grd', vim.diagnostic.open_float, 'Diagnostic popup')
nmap('grn', vim.lsp.buf.rename, 'Rename')
nmap('grr', vim.lsp.buf.references, 'References')

nmap([[\h]], cmd("nohlsearch"), "un-highlight search matches")
nmap([[\d]], function() vim.diagnostic.enable(not vim.diagnostic.is_enabled()) end, "toggle lsp diagnostic")

nmap_leader(';', cmd("Yazi"), "expore files in yazi")

nvoxmap("gy", '"+y')
nmap("<leader>`", "<C-^>", "Alternate buffers")
nmap("<leader>'", cmd "Format", "Alternate buffers")


nvoxmap_leader("gg", luacmd "MiniGit.show_at_cursor()", "Git at cursor")
nvoxmap_leader("gh", luacmd "MiniGit.show_range_history()", "Git history")
nvoxmap_leader("gs", cmd "Git status", "Git status")
nvoxmap_leader("gS", luacmd "MiniGit.show_diff_source()", "Git source")
nmap_leader("gd", luacmd "MiniDiff.toggle_overlay()", "Toggle git diff overlay")
nmap_leader("gq", luacmd "vim.fn.setqflist(MiniDiff.export('qf'));vim.cmd[[copen]]", "Toggle git diff overlay")



nmap("[<tab>", cmd "tabprev", "Tab back")
nmap("]<tab>", cmd "tabnext", "Tab next")

nmap_leader("y", function()
	local file = vim.fn.expand("%:p")           -- absolute path
	local line = vim.api.nvim_win_get_cursor(0)[1] -- current line
	local text = string.format("%s:%d", file, line)

	vim.fn.setreg("+", text) -- copy to system clipboard
	print("Copied: " .. text)
end, { desc = "Copy file:line to clipboard" })
