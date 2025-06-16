#!/bin/bash

# ========================================================================
# 🔒 TESTSSL.SH AUTOMATION SCRIPT
# ========================================================================
# 
# Ce script automatise l'exécution de testssl.sh et l'analyse des résultats
# avec le testssl-analyzer.py pour générer des rapports complets.
#
# Usage: ./testssl_automation.sh domain1.com domain2.com ...
# ========================================================================

set -e  # Exit on any error

# Configuration
TESTSSL_PATH="./testssl.sh/testssl.sh"
ANALYZER_PATH="./testssl-analyzer.py"
OUTPUT_DIR="./testssl_reports"
DATE=$(date +%Y%m%d-%H%M)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_banner() {
    echo "========================================"
    echo "🔒 TESTSSL.SH AUTOMATION SCRIPT"
    echo "========================================"
    echo "Date: $(date)"
    echo "Output Directory: $OUTPUT_DIR"
    echo "========================================"
}

check_dependencies() {
    log_info "Checking dependencies..."
    
    # Check testssl.sh
    if [ ! -f "$TESTSSL_PATH" ]; then
        log_error "testssl.sh not found at $TESTSSL_PATH"
        log_info "Please ensure testssl.sh is available or update TESTSSL_PATH"
        exit 1
    fi
    
    # Check analyzer
    if [ ! -f "$ANALYZER_PATH" ]; then
        log_error "testssl-analyzer.py not found at $ANALYZER_PATH"
        log_info "Please ensure testssl-analyzer.py is available or update ANALYZER_PATH"
        exit 1
    fi
    
    # Check Python dependencies
    if ! python3 -c "import openpyxl, pandas" 2>/dev/null; then
        log_warning "Excel dependencies not installed. Installing..."
        pip3 install openpyxl pandas
    fi
    
    log_success "All dependencies checked"
}

create_output_dir() {
    mkdir -p "$OUTPUT_DIR"
    log_info "Output directory created: $OUTPUT_DIR"
}

scan_domain() {
    local domain=$1
    local port=${2:-443}
    local csv_file="$OUTPUT_DIR/${domain}_p${port}-${DATE}.csv"
    
    log_info "Scanning $domain:$port..."
    
    # Run testssl.sh scan
    if $TESTSSL_PATH --csvfile "$csv_file" --full --protocols --ciphers --vulnerabilities "https://$domain:$port"; then
        log_success "Scan completed for $domain:$port"
        echo "$csv_file"
    else
        log_error "Scan failed for $domain:$port"
        return 1
    fi
}

analyze_results() {
    local csv_files=("$@")
    local report_file="$OUTPUT_DIR/security_analysis_report_${DATE}.xlsx"
    
    log_info "Analyzing results..."
    log_info "CSV files: ${csv_files[*]}"
    
    if python3 "$ANALYZER_PATH" "${csv_files[@]}" -o "$report_file"; then
        log_success "Analysis completed: $report_file"
        return 0
    else
        log_error "Analysis failed"
        return 1
    fi
}

generate_summary_report() {
    local report_file="$OUTPUT_DIR/summary_${DATE}.txt"
    
    log_info "Generating summary report..."
    
    {
        echo "=========================================="
        echo "🔒 TESTSSL.SH SCAN SUMMARY"
        echo "=========================================="
        echo "Date: $(date)"
        echo "Domains Scanned: $#"
        echo ""
        
        for domain in "$@"; do
            echo "📊 Domain: $domain"
            echo "   Status: Scanned"
            echo "   Files: ${domain}_p443-${DATE}.csv"
            echo ""
        done
        
        echo "📝 Reports Generated:"
        echo "   - Excel Report: security_analysis_report_${DATE}.xlsx"
        echo "   - Summary: summary_${DATE}.txt"
        echo ""
        echo "🔍 Next Steps:"
        echo "   1. Review Excel report for detailed analysis"
        echo "   2. Address critical and high-priority issues"
        echo "   3. Schedule follow-up scans"
        echo ""
        echo "=========================================="
    } > "$report_file"
    
    # Also display summary
    cat "$report_file"
    
    log_success "Summary report saved: $report_file"
}

# Main execution
main() {
    print_banner
    
    # Check arguments
    if [ $# -eq 0 ]; then
        log_error "No domains specified"
        echo "Usage: $0 domain1.com [domain2.com] [domain3.com] ..."
        echo ""
        echo "Examples:"
        echo "  $0 example.com"
        echo "  $0 example.com subdomain.example.com"
        echo "  $0 site1.com site2.com site3.com"
        exit 1
    fi
    
    # Setup
    check_dependencies
    create_output_dir
    
    # Scan all domains
    csv_files=()
    failed_domains=()
    
    for domain in "$@"; do
        if csv_file=$(scan_domain "$domain"); then
            csv_files+=("$csv_file")
        else
            failed_domains+=("$domain")
        fi
    done
    
    # Check if any scans succeeded
    if [ ${#csv_files[@]} -eq 0 ]; then
        log_error "All scans failed. No analysis possible."
        exit 1
    fi
    
    # Report failed domains
    if [ ${#failed_domains[@]} -gt 0 ]; then
        log_warning "Failed to scan domains: ${failed_domains[*]}"
    fi
    
    # Analyze results
    if analyze_results "${csv_files[@]}"; then
        generate_summary_report "$@"
        log_success "All operations completed successfully!"
    else
        log_error "Analysis failed but CSV files are available in $OUTPUT_DIR"
        exit 1
    fi
}

# Execute main function with all arguments
main "$@"
