--- @sync entry
return {
    entry = function(_)
        local h = cx.active.current.hovered
        local target = h.url.parent
        ya.dbg(Url(target))

        -- Change directory to the target URL
        ya.emit("cd", { Url(target) })
    end,
}
