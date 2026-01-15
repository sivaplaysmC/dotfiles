#!/usr/bin/env bash

kill -9 $(pgrep -f ${BASH_SOURCE[0]} | grep -v $$) 2>/dev/null

path=/sys/class/backlight/amdgpu_bl1


read -r max < "$path/max_brightness"

print_brightness() {
    read -r level < "$path/brightness"
    percent=$(( level * 100 / max ))
    echo "LIT: <b>$percent%</b>"
}


print_brightness
inotifywait -m -e modify "$path/brightness" | while read; do
    print_brightness
done

