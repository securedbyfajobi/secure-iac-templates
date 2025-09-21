#!/bin/bash

# Security Scan Script for Infrastructure as Code
# Performs comprehensive security scanning of Terraform, CloudFormation, and Ansible files

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SCAN_RESULTS_DIR="${PROJECT_ROOT}/scan-results"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Create results directory
mkdir -p "$SCAN_RESULTS_DIR"

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check if required tools are installed
check_dependencies() {
    local missing_tools=()

    command -v terraform >/dev/null 2>&1 || missing_tools+=("terraform")
    command -v tfsec >/dev/null 2>&1 || missing_tools+=("tfsec")
    command -v checkov >/dev/null 2>&1 || missing_tools+=("checkov")
    command -v ansible-lint >/dev/null 2>&1 || missing_tools+=("ansible-lint")

    if [ ${#missing_tools[@]} -ne 0 ]; then
        error "Missing required tools: ${missing_tools[*]}"
        echo "Please install missing tools:"
        for tool in "${missing_tools[@]}"; do
            case $tool in
                terraform)
                    echo "  - Terraform: https://www.terraform.io/downloads.html"
                    ;;
                tfsec)
                    echo "  - tfsec: go install github.com/aquasecurity/tfsec/cmd/tfsec@latest"
                    ;;
                checkov)
                    echo "  - Checkov: pip install checkov"
                    ;;
                ansible-lint)
                    echo "  - Ansible Lint: pip install ansible-lint"
                    ;;
            esac
        done
        exit 1
    fi
}

# Scan Terraform files with tfsec
scan_terraform_tfsec() {
    log "Running tfsec scan for Terraform files..."

    if find "$PROJECT_ROOT" -name "*.tf" -type f | grep -q .; then
        tfsec "$PROJECT_ROOT" \
            --format json \
            --out "${SCAN_RESULTS_DIR}/tfsec_results_${TIMESTAMP}.json" \
            --soft-fail

        # Generate human-readable report
        tfsec "$PROJECT_ROOT" \
            --format table \
            --out "${SCAN_RESULTS_DIR}/tfsec_report_${TIMESTAMP}.txt" \
            --soft-fail

        success "tfsec scan completed. Results saved to scan-results/"
    else
        warning "No Terraform files found for tfsec scanning"
    fi
}

# Scan with Checkov
scan_checkov() {
    log "Running Checkov scan for infrastructure files..."

    checkov \
        --directory "$PROJECT_ROOT" \
        --output json \
        --output-file-path "${SCAN_RESULTS_DIR}/checkov_results_${TIMESTAMP}.json" \
        --soft-fail

    # Generate summary report
    checkov \
        --directory "$PROJECT_ROOT" \
        --output cli \
        --soft-fail > "${SCAN_RESULTS_DIR}/checkov_report_${TIMESTAMP}.txt"

    success "Checkov scan completed. Results saved to scan-results/"
}

# Scan Ansible playbooks
scan_ansible() {
    log "Running Ansible Lint scan..."

    if find "$PROJECT_ROOT" -name "*.yml" -o -name "*.yaml" | grep -E "(playbook|ansible)" | grep -q .; then
        ansible-lint \
            --parseable \
            --quiet \
            "$PROJECT_ROOT/ansible/" > "${SCAN_RESULTS_DIR}/ansible_lint_${TIMESTAMP}.txt" 2>&1 || true

        success "Ansible Lint scan completed. Results saved to scan-results/"
    else
        warning "No Ansible files found for scanning"
    fi
}

# Custom security checks
run_custom_checks() {
    log "Running custom security checks..."

    local issues_found=0
    local report_file="${SCAN_RESULTS_DIR}/custom_security_checks_${TIMESTAMP}.txt"

    echo "Custom Security Checks Report - $(date)" > "$report_file"
    echo "===========================================" >> "$report_file"
    echo "" >> "$report_file"

    # Check for hardcoded secrets
    echo "Checking for hardcoded secrets..." >> "$report_file"
    if grep -r -i --include="*.tf" --include="*.yaml" --include="*.yml" \
        -E "(password|secret|key)\s*=\s*[\"'][^\"']{8,}[\"']" "$PROJECT_ROOT" >> "$report_file" 2>/dev/null; then
        error "Potential hardcoded secrets found!"
        ((issues_found++))
    else
        echo "No hardcoded secrets detected." >> "$report_file"
    fi

    echo "" >> "$report_file"

    # Check for public access
    echo "Checking for public access configurations..." >> "$report_file"
    if grep -r --include="*.tf" --include="*.yaml" --include="*.yml" \
        -E "(0\.0\.0\.0/0|public|AllUsers)" "$PROJECT_ROOT" >> "$report_file" 2>/dev/null; then
        warning "Public access configurations found - review for security"
        ((issues_found++))
    else
        echo "No obvious public access configurations found." >> "$report_file"
    fi

    echo "" >> "$report_file"

    # Check for missing encryption
    echo "Checking for encryption configurations..." >> "$report_file"
    local unencrypted_count
    unencrypted_count=$(grep -r --include="*.tf" --include="*.yaml" --include="*.yml" \
        -c -i "encrypt" "$PROJECT_ROOT" 2>/dev/null | wc -l || echo 0)

    if [ "$unencrypted_count" -lt 5 ]; then
        warning "Limited encryption configurations found - ensure data is encrypted"
        echo "Limited encryption configurations detected." >> "$report_file"
        ((issues_found++))
    else
        echo "Encryption configurations found: $unencrypted_count files" >> "$report_file"
    fi

    echo "" >> "$report_file"
    echo "Custom checks completed. Issues found: $issues_found" >> "$report_file"

    if [ $issues_found -eq 0 ]; then
        success "Custom security checks passed"
    else
        warning "Custom security checks found $issues_found potential issues"
    fi
}

# Generate consolidated report
generate_summary_report() {
    log "Generating consolidated security report..."

    local summary_file="${SCAN_RESULTS_DIR}/security_summary_${TIMESTAMP}.md"

    cat > "$summary_file" << EOF
# Infrastructure Security Scan Report

**Scan Date:** $(date)
**Project:** $(basename "$PROJECT_ROOT")
**Scan ID:** ${TIMESTAMP}

## Scan Overview

This report contains the results of comprehensive security scanning performed on Infrastructure as Code files.

### Tools Used

- **tfsec**: Terraform static analysis
- **Checkov**: Multi-platform security scanning
- **Ansible Lint**: Ansible playbook analysis
- **Custom Checks**: Project-specific security validations

### Files Scanned

EOF

    # Count files by type
    echo "- **Terraform files:** $(find "$PROJECT_ROOT" -name "*.tf" -type f | wc -l)" >> "$summary_file"
    echo "- **CloudFormation files:** $(find "$PROJECT_ROOT" -name "*.yaml" -o -name "*.yml" | grep -c cloudformation || echo 0)" >> "$summary_file"
    echo "- **Ansible files:** $(find "$PROJECT_ROOT" -name "*.yml" -o -name "*.yaml" | grep -c ansible || echo 0)" >> "$summary_file"

    cat >> "$summary_file" << EOF

## Results Summary

### Critical Issues
- Review critical findings in individual tool reports
- Address high-severity vulnerabilities immediately

### Recommendations
1. Implement encryption for all data at rest and in transit
2. Follow principle of least privilege for IAM policies
3. Enable comprehensive logging and monitoring
4. Regular security scanning in CI/CD pipeline

### Next Steps
1. Review detailed reports in scan-results directory
2. Remediate identified security issues
3. Re-run scans after fixes
4. Integrate scanning into development workflow

EOF

    success "Summary report generated: $summary_file"
}

# Main execution
main() {
    log "Starting Infrastructure Security Scan"
    log "Project: $(basename "$PROJECT_ROOT")"
    log "Timestamp: $TIMESTAMP"

    check_dependencies

    # Run all scans
    scan_terraform_tfsec
    scan_checkov
    scan_ansible
    run_custom_checks

    # Generate summary
    generate_summary_report

    log "Security scan completed successfully!"
    log "Results available in: $SCAN_RESULTS_DIR"

    # Show quick summary
    echo ""
    echo "Quick Summary:"
    echo "=============="
    echo "Scan results directory: $SCAN_RESULTS_DIR"
    echo "Files generated:"
    ls -la "$SCAN_RESULTS_DIR" | grep "$TIMESTAMP" | awk '{print "  - " $9}'
}

# Handle script arguments
case "${1:-scan}" in
    scan)
        main
        ;;
    clean)
        log "Cleaning up old scan results..."
        find "$SCAN_RESULTS_DIR" -name "*_*" -mtime +7 -delete 2>/dev/null || true
        success "Cleanup completed"
        ;;
    --help|-h)
        echo "Usage: $0 [scan|clean|--help]"
        echo ""
        echo "Commands:"
        echo "  scan    - Run security scan (default)"
        echo "  clean   - Clean up old scan results"
        echo "  --help  - Show this help message"
        ;;
    *)
        error "Unknown command: $1"
        echo "Use --help for usage information"
        exit 1
        ;;
esac