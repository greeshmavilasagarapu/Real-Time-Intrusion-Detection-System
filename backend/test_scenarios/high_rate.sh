#!/bin/bash
# Test Scenario 3: High-Rate Network Activity
# Generates burst traffic to trigger flow-level detection.
# SAFE: Only targets localhost

echo "========================================="
echo "  TEST: High-Rate Network Activity"
echo "========================================="
echo "Sending 200 rapid HTTP requests..."
echo ""

# Start a simple HTTP server on port 8888 if not running
python3 -m http.server 8888 --bind 127.0.0.1 &
SERVER_PID=$!
sleep 1

# Generate burst traffic
for i in $(seq 1 200); do
    curl -s http://127.0.0.1:8888/ -o /dev/null &
    # Don't wait - fire them all
done

# Wait for requests to complete
wait

# Also generate some DNS-like activity
for i in $(seq 1 50); do
    nslookup nonexistent_test_$(date +%s).example.com 2>/dev/null &
done
wait

kill $SERVER_PID 2>/dev/null

echo ""
echo "Done! Check the dashboard for high-rate traffic detection."
echo "Expected: Network flows with high packet/byte rates."
