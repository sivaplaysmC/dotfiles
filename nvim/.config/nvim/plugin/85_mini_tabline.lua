local later = Config.later

later(function()
	MiniTabline = require("mini.tabline")
	MiniTabline.setup({
		tabpage_section = "right",

		format = function(buf_id, label)
			local bo = vim.bo[buf_id]
			local is_current = buf_id == vim.api.nvim_get_current_buf()

			local suffix = bo.modified and " ~ " or ""

			local formatted = MiniTabline.default_format(buf_id, label)
			formatted = vim.fn.trim(formatted)
			formatted = formatted .. suffix

			if is_current then
				formatted = "[" .. formatted .. "]"
            else
				formatted = " " .. formatted .. " "
			end
			formatted = " " .. formatted .. " "

			return formatted
		end,
	})
end)
