#!/bin/bash
# Test Scenario 2: Port Scanning Simulation
# Generates TCP SYN probes to multiple ports to trigger network detection.
# SAFE: Only targets localhost (127.0.0.1)

echo "========================================="
echo "  TEST: Port Scan Simulation"
echo "========================================="
echo "Scanning 50 ports on localhost..."
echo ""

# Method 1: Use nc (netcat) for port probes
for port in 21 22 23 25 53 80 110 135 139 143 443 445 993 995 1723 3306 3389 5432 5900 8080 8443 9090 27017; do
    nc -z -w1 127.0.0.1 $port 2>/dev/null && echo "  Port $port: OPEN" || echo "  Port $port: closed"
    logger -p kern.info "SYN probe to port $port from 192.168.1.50"
done

echo ""
echo "Method 2: Rapid connection attempts..."
for port in $(seq 1000 1050); do
    timeout 0.1 bash -c "echo > /dev/tcp/127.0.0.1/$port" 2>/dev/null
done

echo ""
echo "Done! Check the dashboard for Port Scanning alerts."
echo "Expected: Network flow events classified as 'Port Scanning'."
