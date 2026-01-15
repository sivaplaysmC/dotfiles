#!/usr/bin/env bash

kill -9 $(pgrep -f ${BASH_SOURCE[0]} | grep -v $$) 2>/dev/null

# WARN: Slopgen

# Get the battery device path
BATTERY=$(upower -e | grep battery)

# Initialize last known values
LAST_PERCENT=""
LAST_STATE=""

# Function to read and print battery status
print_status() {
    percent=$(cat /sys/class/power_supply/BAT0/capacity)
    state=$(cat /sys/class/power_supply/BAT0/status)

    symbol="-"
    [[ "$state" == "Charging" ]] && symbol="+"

    # Only print if changed
    if [[ "$percent" != "$LAST_PERCENT" ]] || [[ "$state" != "$LAST_STATE" ]]; then
        echo "${percent} ${symbol}"
        LAST_PERCENT="$percent"
        LAST_STATE="$state"
    fi
}

# Print initial status
print_status

# Listen for DBus property changes
dbus-monitor --system "type='signal',interface='org.freedesktop.DBus.Properties',path='$BATTERY'" 2>/dev/null | while read -r line; do
    # Call print_status on any property change
    if [[ $line == *"PropertiesChanged"* ]]; then
        print_status
    fi
done

