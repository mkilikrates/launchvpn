#!/bin/bash

while true; do
    ping -c 1 $1 &> /dev/null
    ping -c 1 $2 &> /dev/null
    sleep 5
done
