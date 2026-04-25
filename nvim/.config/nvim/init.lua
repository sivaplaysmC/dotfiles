vim.g.loaded_gzip = 1
vim.g.loaded_matchit = 1
vim.g.loaded_matchparen = 1
vim.g.loaded_netrwPlugin = 1
vim.g.loaded_tarPlugin = 1
vim.g.loaded_tohtml = 1
vim.g.loaded_tutor = 1
vim.g.loaded_zipPlugin = 1

vim.pack.add({ "https://github.com/nvim-mini/mini.nvim" })

local misc = require("mini.misc")
local later = function(f)
    misc.safely("later", f)
end
local on_event = function(ev, f)
    misc.safely("event:" .. ev, f)
end
local now = function(x)
	misc.safely("now", x)
end
local now_if_args = vim.fn.argc(-1) > 0 and now or later
local now_if_no_args = vim.fn.argc(-1) > 0 and later or now

local gr = vim.api.nvim_create_augroup("custom-config", {})
local new_autocmd = function(event, pattern, callback, desc)
    local opts = { group = gr, pattern = pattern, callback = callback, desc = desc }
    vim.api.nvim_create_autocmd(event, opts)
end

_G.Config = {
    later = later,
    on_event = on_event,
    now = now,
    new_autocmd = new_autocmd,
    now_if_args = now_if_args,
	now_if_no_args = now_if_no_args,
}

require("vim._core.ui2").enable({
    enable = true,
    msg = {
        targets = {
            [""] = "msg",
            empty = "cmd",
            bufwrite = "cmd",
            confirm = "cmd",
            emsg = "pager",
            echo = "msg",
            echomsg = "msg",
            echoerr = "pager",
            completion = "cmd",
            list_cmd = "pager",
            lua_error = "pager",
            lua_print = "msg",
            progress = "pager",
            rpc_error = "pager",
            quickfix = "msg",
            search_cmd = "cmd",
            search_count = "cmd",
            shell_cmd = "pager",
            shell_err = "pager",
            shell_out = "pager",
            shell_ret = "msg",

            undo = "msg",
            verbose = "pager",
            wildlist = "cmd",
            wmsg = "pager",
            typed_cmd = "cmd",
        },
        cmd = {
            height = 0.5,
        },
        dialog = {
            height = 0.5,
        },
        msg = {
            height = 0.3,
            timeout = 5000,
        },
        pager = {
            height = 0.5,
        },
    },
})
