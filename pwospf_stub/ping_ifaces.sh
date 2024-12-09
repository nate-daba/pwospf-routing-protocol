#!/bin/bash

# File containing the IP list
IPLIST_FILE="vnltopo113.iplist"

# Check if the file exists
if [[ ! -f "$IPLIST_FILE" ]]; then
    echo "File $IPLIST_FILE not found!"
    exit 1
fi

# Loop through each line in the file
while IFS='=' read -r key value; do
    # Skip empty lines or lines without an equals sign
    if [[ -z "$key" || -z "$value" ]]; then
        continue
    fi

    # Extract the IP address
    IP=$(echo "$value" | xargs) # Trim whitespace

    # Extract the descriptive information from the key
    if [[ "$key" =~ ip_(.+)_eth([0-9]+) ]]; then
        HOST=${BASH_REMATCH[1]} # e.g., vhost1
        INTERFACE=eth${BASH_REMATCH[2]} # e.g., eth0
    else
        HOST="unknown host"
        INTERFACE="unknown interface"
    fi

    # Display the descriptive message
    echo "====================================================="
    echo "Pinging interface $INTERFACE of $HOST at $IP..."
    echo "====================================================="

    # Ping the IP 10 times
    ping -c 10 "$IP"

    # Check if the ping was successful
    if [[ $? -eq 0 ]]; then
        echo "Ping to $IP successful."
    else
        echo "Ping to $IP failed."
    fi

    echo "-----------------------------------------------------"
done < "$IPLIST_FILE"

echo "Ping operations completed."
