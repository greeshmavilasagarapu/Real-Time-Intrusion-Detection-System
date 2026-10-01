#!/bin/bash
# Test Scenario 1: Brute Force Login Simulation
# Generates repeated failed SSH login attempts to trigger log anomaly detection.
# SAFE: Only targets localhost, uses invalid credentials.

echo "========================================="
echo "  TEST: Brute Force Login Simulation"
echo "========================================="
echo "Generating 20 failed SSH login attempts..."
echo ""

for i in $(seq 1 20); do
    # These generate auth.log entries on most Linux systems
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=1 -o PasswordAuthentication=no \
        nonexistent_user_$(date +%s)@127.0.0.1 2>/dev/null
    
    # Also generate syslog entries
    logger -p auth.warning "Failed password for invalid user testuser${i} from 192.168.1.100 port ${i}5555 ssh2"
    logger -p auth.info "Connection closed by 127.0.0.1 port ${i}5555 [preauth]"
    
    echo "  Attempt $i: logged"
    sleep 0.5
done

echo ""
echo "Done! Check the dashboard for log anomaly alerts."
echo "Expected: 'Log Anomaly' events with LIME explanations."
