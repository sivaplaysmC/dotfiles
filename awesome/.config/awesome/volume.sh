#!/usr/bin/env bash

kill -9 $(pgrep -f ${BASH_SOURCE[0]} | grep -v $$) 2>/dev/null

# Get the default sink
DEFAULT_SINK=$(pactl get-default-sink)

# Function to print current volume or "MUT" if muted
print_volume() {
    pactl get-sink-mute "$DEFAULT_SINK" | grep -q yes && echo "MUT" && return
    pactl get-sink-volume "$DEFAULT_SINK" | awk '{print $5}' | head -n1
}

# Print initial volume
cont=$(print_volume)
echo "VOL: <b>$cont</b>"

pactl subscribe | grep --line-buffered "change' on sink" | while read -r line; do
    cont=$(print_volume)
    echo "VOL: <b>$cont</b>"
done

