-- ~/.config/nvim/plugin/qf.lua

-- Toggle quickfix
vim.keymap.set("n", "<C-q>", function()
  local win = nil
  for _, w in ipairs(vim.api.nvim_list_wins()) do
    if vim.bo[vim.api.nvim_win_get_buf(w)].buftype == "quickfix" then
      win = w
      break
    end
  end
  vim.cmd(win and "cclose" or "copen")
end, { desc = "Toggle quickfix", silent = true })

local group = vim.api.nvim_create_augroup("QuickfixGuard", { clear = true })

-- If the QF buffer is killed, close the window
vim.api.nvim_create_autocmd("BufWipeout", {
  group = group,
  callback = function(ev)
    if vim.bo[ev.buf].buftype == "quickfix" then
      vim.schedule(function() vim.cmd("cclose") end)
    end
  end,
})

-- Prevent non-QF buffers from loading into the QF window
vim.api.nvim_create_autocmd("BufWinEnter", {
  group = group,
  callback = function(ev)
    local win = vim.api.nvim_get_current_win()
    -- Is this window currently showing a QF buffer?
    local cur_buf = vim.api.nvim_win_get_buf(win)
    if vim.bo[cur_buf].buftype ~= "quickfix" then return end
    -- Is the buffer being entered NOT a QF buffer?
    if vim.bo[ev.buf].buftype == "quickfix" then return end

    -- Kick it out: close QF and open the buffer in the previous window
    vim.cmd("cclose")
    vim.cmd("wincmd p")
    vim.cmd("buffer " .. ev.buf)
  end,
})
