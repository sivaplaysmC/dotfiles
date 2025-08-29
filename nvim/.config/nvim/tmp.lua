
local enabled_langservers = {
    "lua-language-server",
    "gopls",
    "clangd",
    "basedpyright",
}

for _, langserver in ipairs(enabled_langservers) do
    vim.lsp.enable(langserver)
end
