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

    # Ping the IP 15 times
    echo "Pinging $IP..."
    ping -c 10 "$IP"

    # Check if the ping was successful
    if [[ $? -eq 0 ]]; then
        echo "Ping to $IP successful."
    else
        echo "Ping to $IP failed."
    fi

    echo "-----------------------------"
done < "$IPLIST_FILE"

echo "Ping operations completed."
