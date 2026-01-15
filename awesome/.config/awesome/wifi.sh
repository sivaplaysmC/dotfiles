#!/usr/bin/env bash

kill -9 $(pgrep -f ${BASH_SOURCE[0]} | grep -v $$) 2>/dev/null

last_ap=""

print_current_ap() {
    # Read two lines from nmcli output into variables
    {
        read -r ip_addr
        read -r ap_name
    } < <(nmcli -g IP4.ADDRESS,GENERAL.CONNECTION device show wlp3s0)

    if [[ -z "$ap_name" ]]; then
        echo "NOWIFI"
    else
        echo "$ap_name $ip_addr"
    fi
}

print_current_ap

# Monitor NetworkManager events
nmcli monitor | while read -r line; do
    case "$line" in
        *"wlp3s0: disconnected"*|*"wlp3s0: connected"*)
            print_current_ap  # This will run for both connected and disconnected
            ;;
        *)
            # ignore other lines
            ;;
    esac
done


