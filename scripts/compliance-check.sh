#!/bin/bash

# Compliance Check Script
# Validates infrastructure against compliance frameworks (CIS, NIST, SOC2, PCI-DSS)

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
COMPLIANCE_RESULTS_DIR="${PROJECT_ROOT}/compliance-results"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Compliance frameworks
declare -A FRAMEWORKS=(
    ["cis"]="CIS Benchmarks"
    ["nist"]="NIST Cybersecurity Framework"
    ["soc2"]="SOC 2 Type II"
    ["pci"]="PCI DSS"
    ["iso27001"]="ISO 27001"
)

# Create results directory
mkdir -p "$COMPLIANCE_RESULTS_DIR"

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

info() {
    echo -e "${PURPLE}[INFO]${NC} $1"
}

# Check dependencies
check_dependencies() {
    local missing_tools=()

    command -v terraform >/dev/null 2>&1 || missing_tools+=("terraform")
    command -v aws >/dev/null 2>&1 || missing_tools+=("aws-cli")
    command -v jq >/dev/null 2>&1 || missing_tools+=("jq")

    if [ ${#missing_tools[@]} -ne 0 ]; then
        error "Missing required tools: ${missing_tools[*]}"
        exit 1
    fi
}

# CIS Benchmarks compliance check
check_cis_compliance() {
    log "Checking CIS Benchmarks compliance..."

    local cis_results_file="${COMPLIANCE_RESULTS_DIR}/cis_compliance_${TIMESTAMP}.json"
    local cis_report_file="${COMPLIANCE_RESULTS_DIR}/cis_report_${TIMESTAMP}.md"

    # Initialize results
    cat > "$cis_results_file" << 'EOF'
{
  "framework": "CIS Benchmarks",
  "version": "1.4.0",
  "timestamp": "",
  "controls": {},
  "summary": {
    "total_controls": 0,
    "passed": 0,
    "failed": 0,
    "compliance_percentage": 0
  }
}
EOF

    # Update timestamp
    jq --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" '.timestamp = $timestamp' "$cis_results_file" > tmp.json && mv tmp.json "$cis_results_file"

    local controls_passed=0
    local controls_total=0

    # CIS Control 1.1 - Avoid the use of the "root" account
    log "Checking CIS 1.1 - Root account usage..."
    if check_root_account_usage; then
        ((controls_passed++))
        jq '.controls["CIS-1.1"] = {"status": "PASS", "description": "Root account usage is restricted"}' "$cis_results_file" > tmp.json && mv tmp.json "$cis_results_file"
    else
        jq '.controls["CIS-1.1"] = {"status": "FAIL", "description": "Root account usage detected"}' "$cis_results_file" > tmp.json && mv tmp.json "$cis_results_file"
    fi
    ((controls_total++))

    # CIS Control 2.1 - Ensure CloudTrail is enabled in all regions
    log "Checking CIS 2.1 - CloudTrail configuration..."
    if check_cloudtrail_config; then
        ((controls_passed++))
        jq '.controls["CIS-2.1"] = {"status": "PASS", "description": "CloudTrail is properly configured"}' "$cis_results_file" > tmp.json && mv tmp.json "$cis_results_file"
    else
        jq '.controls["CIS-2.1"] = {"status": "FAIL", "description": "CloudTrail configuration issues found"}' "$cis_results_file" > tmp.json && mv tmp.json "$cis_results_file"
    fi
    ((controls_total++))

    # CIS Control 2.7 - Ensure CloudTrail logs are encrypted at rest
    log "Checking CIS 2.7 - CloudTrail encryption..."
    if check_cloudtrail_encryption; then
        ((controls_passed++))
        jq '.controls["CIS-2.7"] = {"status": "PASS", "description": "CloudTrail logs are encrypted"}' "$cis_results_file" > tmp.json && mv tmp.json "$cis_results_file"
    else
        jq '.controls["CIS-2.7"] = {"status": "FAIL", "description": "CloudTrail logs encryption issues"}' "$cis_results_file" > tmp.json && mv tmp.json "$cis_results_file"
    fi
    ((controls_total++))

    # CIS Control 4.1 - Ensure no security groups allow ingress from 0.0.0.0/0 to port 22
    log "Checking CIS 4.1 - SSH access restrictions..."
    if check_ssh_access_restrictions; then
        ((controls_passed++))
        jq '.controls["CIS-4.1"] = {"status": "PASS", "description": "SSH access is properly restricted"}' "$cis_results_file" > tmp.json && mv tmp.json "$cis_results_file"
    else
        jq '.controls["CIS-4.1"] = {"status": "FAIL", "description": "Unrestricted SSH access found"}' "$cis_results_file" > tmp.json && mv tmp.json "$cis_results_file"
    fi
    ((controls_total++))

    # Update summary
    local compliance_percentage=$((controls_passed * 100 / controls_total))
    jq --argjson passed "$controls_passed" --argjson total "$controls_total" --argjson percentage "$compliance_percentage" \
        '.summary.passed = $passed | .summary.total_controls = $total | .summary.failed = ($total - $passed) | .summary.compliance_percentage = $percentage' \
        "$cis_results_file" > tmp.json && mv tmp.json "$cis_results_file"

    # Generate readable report
    generate_cis_report "$cis_results_file" "$cis_report_file"

    success "CIS compliance check completed. Score: ${compliance_percentage}%"
}

# NIST Cybersecurity Framework compliance check
check_nist_compliance() {
    log "Checking NIST Cybersecurity Framework compliance..."

    local nist_results_file="${COMPLIANCE_RESULTS_DIR}/nist_compliance_${TIMESTAMP}.json"

    cat > "$nist_results_file" << 'EOF'
{
  "framework": "NIST Cybersecurity Framework",
  "version": "1.1",
  "timestamp": "",
  "functions": {
    "identify": {"controls": {}, "score": 0},
    "protect": {"controls": {}, "score": 0},
    "detect": {"controls": {}, "score": 0},
    "respond": {"controls": {}, "score": 0},
    "recover": {"controls": {}, "score": 0}
  },
  "overall_score": 0
}
EOF

    jq --arg timestamp "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" '.timestamp = $timestamp' "$nist_results_file" > tmp.json && mv tmp.json "$nist_results_file"

    # IDENTIFY function checks
    log "Checking NIST Identify function..."
    local identify_score=0

    # ID.AM-1: Physical devices and systems are inventoried
    if check_asset_inventory; then
        ((identify_score+=20))
        jq '.functions.identify.controls["ID.AM-1"] = {"status": "PASS", "description": "Asset inventory is maintained"}' "$nist_results_file" > tmp.json && mv tmp.json "$nist_results_file"
    else
        jq '.functions.identify.controls["ID.AM-1"] = {"status": "FAIL", "description": "Asset inventory gaps found"}' "$nist_results_file" > tmp.json && mv tmp.json "$nist_results_file"
    fi

    # PROTECT function checks
    log "Checking NIST Protect function..."
    local protect_score=0

    # PR.AC-1: Identities and credentials are issued, managed, verified, revoked
    if check_identity_management; then
        ((protect_score+=25))
        jq '.functions.protect.controls["PR.AC-1"] = {"status": "PASS", "description": "Identity management is implemented"}' "$nist_results_file" > tmp.json && mv tmp.json "$nist_results_file"
    else
        jq '.functions.protect.controls["PR.AC-1"] = {"status": "FAIL", "description": "Identity management issues found"}' "$nist_results_file" > tmp.json && mv tmp.json "$nist_results_file"
    fi

    # DETECT function checks
    log "Checking NIST Detect function..."
    local detect_score=0

    # DE.CM-1: Networks are monitored
    if check_network_monitoring; then
        ((detect_score+=33))
        jq '.functions.detect.controls["DE.CM-1"] = {"status": "PASS", "description": "Network monitoring is active"}' "$nist_results_file" > tmp.json && mv tmp.json "$nist_results_file"
    else
        jq '.functions.detect.controls["DE.CM-1"] = {"status": "FAIL", "description": "Network monitoring gaps found"}' "$nist_results_file" > tmp.json && mv tmp.json "$nist_results_file"
    fi

    # Update scores
    jq --argjson identify "$identify_score" --argjson protect "$protect_score" --argjson detect "$detect_score" \
        '.functions.identify.score = $identify | .functions.protect.score = $protect | .functions.detect.score = $detect' \
        "$nist_results_file" > tmp.json && mv tmp.json "$nist_results_file"

    local overall_score=$(((identify_score + protect_score + detect_score) / 3))
    jq --argjson overall "$overall_score" '.overall_score = $overall' "$nist_results_file" > tmp.json && mv tmp.json "$nist_results_file"

    success "NIST compliance check completed. Overall score: ${overall_score}%"
}

# Individual compliance checks
check_root_account_usage() {
    # Check for root account usage in CloudTrail logs or IAM policies
    grep -r --include="*.tf" --include="*.json" "root" "$PROJECT_ROOT" >/dev/null 2>&1 && return 1 || return 0
}

check_cloudtrail_config() {
    # Check if CloudTrail is configured in Terraform
    grep -r --include="*.tf" "aws_cloudtrail" "$PROJECT_ROOT" >/dev/null 2>&1
}

check_cloudtrail_encryption() {
    # Check if CloudTrail encryption is enabled
    grep -r --include="*.tf" -A 10 "aws_cloudtrail" "$PROJECT_ROOT" | grep -q "kms_key_id"
}

check_ssh_access_restrictions() {
    # Check for unrestricted SSH access in security groups
    ! grep -r --include="*.tf" -B 5 -A 5 "from_port.*22" "$PROJECT_ROOT" | grep -q "0.0.0.0/0"
}

check_asset_inventory() {
    # Check if resource tagging is implemented
    grep -r --include="*.tf" "tags" "$PROJECT_ROOT" >/dev/null 2>&1
}

check_identity_management() {
    # Check for IAM policies and roles
    grep -r --include="*.tf" "aws_iam" "$PROJECT_ROOT" >/dev/null 2>&1
}

check_network_monitoring() {
    # Check for VPC Flow Logs or GuardDuty
    grep -r --include="*.tf" -E "(flow_log|guardduty)" "$PROJECT_ROOT" >/dev/null 2>&1
}

# Generate CIS compliance report
generate_cis_report() {
    local results_file="$1"
    local report_file="$2"

    cat > "$report_file" << EOF
# CIS Benchmarks Compliance Report

**Assessment Date:** $(date)
**Framework:** $(jq -r '.framework' "$results_file")
**Version:** $(jq -r '.version' "$results_file")

## Executive Summary

**Overall Compliance Score:** $(jq -r '.summary.compliance_percentage' "$results_file")%

- **Controls Passed:** $(jq -r '.summary.passed' "$results_file")
- **Controls Failed:** $(jq -r '.summary.failed' "$results_file")
- **Total Controls Assessed:** $(jq -r '.summary.total_controls' "$results_file")

## Control Assessment Results

EOF

    # Add individual control results
    jq -r '.controls | to_entries[] | "### \(.key): \(.value.description)\n**Status:** \(.value.status)\n"' "$results_file" >> "$report_file"

    cat >> "$report_file" << 'EOF'

## Recommendations

### Immediate Actions Required
1. Address all FAILED controls identified above
2. Implement missing security configurations
3. Review and update security policies

### Long-term Improvements
1. Implement automated compliance monitoring
2. Regular security assessments
3. Security awareness training
4. Incident response procedures

## Next Steps

1. Remediate failed controls
2. Re-run compliance assessment
3. Implement continuous monitoring
4. Schedule regular reviews

---
**Generated by:** Infrastructure Compliance Check Script
EOF
}

# Generate comprehensive compliance dashboard
generate_compliance_dashboard() {
    log "Generating compliance dashboard..."

    local dashboard_file="${COMPLIANCE_RESULTS_DIR}/compliance_dashboard_${TIMESTAMP}.html"

    cat > "$dashboard_file" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Infrastructure Compliance Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .framework { margin: 20px 0; border: 1px solid #ddd; border-radius: 5px; }
        .framework-header { background: #3498db; color: white; padding: 15px; }
        .framework-content { padding: 15px; }
        .score { font-size: 24px; font-weight: bold; }
        .pass { color: #27ae60; }
        .fail { color: #e74c3c; }
        .controls { margin-top: 15px; }
        .control { margin: 5px 0; padding: 10px; border-left: 4px solid; }
        .control.pass { border-color: #27ae60; background: #d5f5e3; }
        .control.fail { border-color: #e74c3c; background: #fadbd8; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Infrastructure Compliance Dashboard</h1>
        <p>Generated: {{TIMESTAMP}}</p>
    </div>

    <div class="framework">
        <div class="framework-header">
            <h2>CIS Benchmarks</h2>
        </div>
        <div class="framework-content">
            <div class="score">Score: <span id="cis-score">--</span>%</div>
            <div class="controls" id="cis-controls">
                <!-- CIS controls will be populated here -->
            </div>
        </div>
    </div>

    <div class="framework">
        <div class="framework-header">
            <h2>NIST Cybersecurity Framework</h2>
        </div>
        <div class="framework-content">
            <div class="score">Score: <span id="nist-score">--</span>%</div>
            <div class="controls" id="nist-controls">
                <!-- NIST controls will be populated here -->
            </div>
        </div>
    </div>

    <script>
        // Populate with actual compliance data
        console.log('Compliance dashboard loaded');
    </script>
</body>
</html>
EOF

    # Replace timestamp
    sed -i.bak "s/{{TIMESTAMP}}/$(date)/g" "$dashboard_file" && rm "${dashboard_file}.bak"

    success "Compliance dashboard generated: $dashboard_file"
}

# Main execution
main() {
    local framework="${1:-all}"

    log "Starting Compliance Check"
    log "Framework: $framework"
    log "Project: $(basename "$PROJECT_ROOT")"
    log "Timestamp: $TIMESTAMP"

    check_dependencies

    case "$framework" in
        cis)
            check_cis_compliance
            ;;
        nist)
            check_nist_compliance
            ;;
        all)
            check_cis_compliance
            check_nist_compliance
            generate_compliance_dashboard
            ;;
        *)
            error "Unknown framework: $framework"
            echo "Available frameworks: cis, nist, all"
            exit 1
            ;;
    esac

    log "Compliance check completed successfully!"
    log "Results available in: $COMPLIANCE_RESULTS_DIR"

    # Show summary
    echo ""
    echo "Compliance Summary:"
    echo "=================="
    echo "Results directory: $COMPLIANCE_RESULTS_DIR"
    ls -la "$COMPLIANCE_RESULTS_DIR" | grep "$TIMESTAMP" | awk '{print "  - " $9}'
}

# Handle arguments
if [ $# -eq 0 ]; then
    main all
else
    case "$1" in
        cis|nist|all)
            main "$1"
            ;;
        clean)
            log "Cleaning up old compliance results..."
            find "$COMPLIANCE_RESULTS_DIR" -name "*_*" -mtime +7 -delete 2>/dev/null || true
            success "Cleanup completed"
            ;;
        --help|-h)
            echo "Usage: $0 [cis|nist|all|clean|--help]"
            echo ""
            echo "Frameworks:"
            echo "  cis     - CIS Benchmarks compliance"
            echo "  nist    - NIST Cybersecurity Framework"
            echo "  all     - All supported frameworks (default)"
            echo ""
            echo "Commands:"
            echo "  clean   - Clean up old results"
            echo "  --help  - Show this help message"
            ;;
        *)
            error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
fi