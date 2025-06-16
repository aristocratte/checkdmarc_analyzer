#!/bin/bash

# ========================================================================
# 🧪 TEST SCRIPT - TESTSSL.SH INTEGRATION VERIFICATION
# ========================================================================
# 
# Ce script teste l'intégration entre testssl.sh et testssl-analyzer.py
# ========================================================================

set -e

# Configuration
TEST_DOMAIN="example.com"
TEST_DIR="./test_testssl_integration"
TESTSSL_PATH="./testssl.sh/testssl.sh"
ANALYZER_PATH="./testssl-analyzer.py"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "========================================"
echo "🧪 Testing TestSSL.sh Integration"
echo "========================================"

# Créer le répertoire de test
mkdir -p "$TEST_DIR"
echo -e "${BLUE}[INFO]${NC} Created test directory: $TEST_DIR"

# Test 1: Vérifier que testssl.sh existe
echo -e "\n${BLUE}[TEST 1]${NC} Checking testssl.sh availability..."
if [ -f "$TESTSSL_PATH" ]; then
    echo -e "${GREEN}[PASS]${NC} testssl.sh found at $TESTSSL_PATH"
else
    echo -e "${RED}[FAIL]${NC} testssl.sh not found at $TESTSSL_PATH"
    exit 1
fi

# Test 2: Vérifier que testssl-analyzer.py existe
echo -e "\n${BLUE}[TEST 2]${NC} Checking testssl-analyzer.py availability..."
if [ -f "$ANALYZER_PATH" ]; then
    echo -e "${GREEN}[PASS]${NC} testssl-analyzer.py found at $ANALYZER_PATH"
else
    echo -e "${RED}[FAIL]${NC} testssl-analyzer.py not found at $ANALYZER_PATH"
    exit 1
fi

# Test 3: Tester la génération CSV avec testssl.sh
echo -e "\n${BLUE}[TEST 3]${NC} Testing CSV generation with testssl.sh..."
CSV_FILE="$TEST_DIR/test_scan.csv"
JSON_FILE="$TEST_DIR/test_scan.json"

echo -e "${YELLOW}[INFO]${NC} Running testssl.sh scan on $TEST_DOMAIN..."
if $TESTSSL_PATH --quiet --color 0 --csvfile "$CSV_FILE" --jsonfile "$JSON_FILE" "https://$TEST_DOMAIN" 2>/dev/null; then
    echo -e "${GREEN}[PASS]${NC} testssl.sh scan completed"
    
    # Vérifier que le fichier CSV a été créé
    if [ -f "$CSV_FILE" ]; then
        echo -e "${GREEN}[PASS]${NC} CSV file created: $CSV_FILE"
        echo -e "${YELLOW}[INFO]${NC} CSV file size: $(wc -l < "$CSV_FILE") lines"
    else
        echo -e "${RED}[FAIL]${NC} CSV file not created"
        exit 1
    fi
else
    echo -e "${RED}[FAIL]${NC} testssl.sh scan failed"
    exit 1
fi

# Test 4: Tester l'analyse avec testssl-analyzer.py
echo -e "\n${BLUE}[TEST 4]${NC} Testing analysis with testssl-analyzer.py..."
EXCEL_FILE="$TEST_DIR/test_analysis.xlsx"

echo -e "${YELLOW}[INFO]${NC} Running testssl-analyzer.py..."
if python3 "$ANALYZER_PATH" "$CSV_FILE" -o "$EXCEL_FILE" >/dev/null 2>&1; then
    echo -e "${GREEN}[PASS]${NC} testssl-analyzer.py completed successfully"
    
    # Vérifier que le fichier Excel a été créé
    if [ -f "$EXCEL_FILE" ]; then
        echo -e "${GREEN}[PASS]${NC} Excel file created: $EXCEL_FILE"
        echo -e "${YELLOW}[INFO]${NC} Excel file size: $(ls -lh "$EXCEL_FILE" | awk '{print $5}')"
    else
        echo -e "${RED}[FAIL]${NC} Excel file not created"
        exit 1
    fi
else
    echo -e "${RED}[FAIL]${NC} testssl-analyzer.py failed"
    exit 1
fi

# Test 5: Tester l'analyse console
echo -e "\n${BLUE}[TEST 5]${NC} Testing console analysis..."
if python3 "$ANALYZER_PATH" "$CSV_FILE" --console-only >/dev/null 2>&1; then
    echo -e "${GREEN}[PASS]${NC} Console analysis completed successfully"
else
    echo -e "${RED}[FAIL]${NC} Console analysis failed"
    exit 1
fi

# Résumé
echo -e "\n========================================"
echo -e "${GREEN}✅ ALL TESTS PASSED!${NC}"
echo "========================================"
echo "Generated files:"
echo "  - CSV: $CSV_FILE"
echo "  - JSON: $JSON_FILE"
echo "  - Excel: $EXCEL_FILE"
echo ""
echo "Integration is working correctly!"
echo "========================================"

# Nettoyer (optionnel)
read -p "Do you want to clean up test files? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf "$TEST_DIR"
    echo -e "${BLUE}[INFO]${NC} Test files cleaned up"
fi
