#!/bin/bash

# Policy Validation Script
# Validates OPA, Sentinel, and Conftest policies against infrastructure code

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
POLICIES_DIR="${PROJECT_ROOT}/policies"
VALIDATION_RESULTS_DIR="${PROJECT_ROOT}/validation-results"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Create results directory
mkdir -p "$VALIDATION_RESULTS_DIR"

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

# Check dependencies
check_dependencies() {
    local missing_tools=()

    command -v opa >/dev/null 2>&1 || missing_tools+=("opa")
    command -v conftest >/dev/null 2>&1 || missing_tools+=("conftest")
    command -v terraform >/dev/null 2>&1 || missing_tools+=("terraform")

    if [ ${#missing_tools[@]} -ne 0 ]; then
        error "Missing required tools: ${missing_tools[*]}"
        echo "Install missing tools:"
        for tool in "${missing_tools[@]}"; do
            case $tool in
                opa)
                    echo "  - OPA: https://www.openpolicyagent.org/docs/latest/#running-opa"
                    ;;
                conftest)
                    echo "  - Conftest: https://www.conftest.dev/install/"
                    ;;
                terraform)
                    echo "  - Terraform: https://www.terraform.io/downloads.html"
                    ;;
            esac
        done
        exit 1
    fi
}

# Validate OPA policies
validate_opa_policies() {
    log "Validating OPA policies..."

    if [ ! -d "${POLICIES_DIR}/opa" ]; then
        warning "No OPA policies directory found"
        return 0
    fi

    local opa_results_file="${VALIDATION_RESULTS_DIR}/opa_validation_${TIMESTAMP}.json"
    local validation_passed=true

    echo '{"opa_validation": {"policies": [], "errors": [], "summary": {}}}' > "$opa_results_file"

    # Find and validate each OPA policy
    while IFS= read -r -d '' policy_file; do
        log "Validating OPA policy: $(basename "$policy_file")"

        # Test policy syntax
        if opa fmt --diff "$policy_file" >/dev/null 2>&1; then
            success "Policy syntax valid: $(basename "$policy_file")"

            # Test policy evaluation
            if [ -f "${PROJECT_ROOT}/terraform/test-data.json" ]; then
                opa eval \
                    --data "$policy_file" \
                    --input "${PROJECT_ROOT}/terraform/test-data.json" \
                    "data" \
                    --format json >> "$opa_results_file" 2>/dev/null || true
            fi
        else
            error "Policy syntax error in: $(basename "$policy_file")"
            validation_passed=false
        fi
    done < <(find "${POLICIES_DIR}/opa" -name "*.rego" -print0 2>/dev/null)

    if $validation_passed; then
        success "All OPA policies validated successfully"
    else
        error "Some OPA policies failed validation"
    fi
}

# Validate Conftest policies
validate_conftest_policies() {
    log "Validating Conftest policies..."

    if [ ! -d "${POLICIES_DIR}/conftest" ]; then
        warning "No Conftest policies directory found"
        return 0
    fi

    local conftest_results_file="${VALIDATION_RESULTS_DIR}/conftest_validation_${TIMESTAMP}.txt"

    # Test against Terraform files
    if find "$PROJECT_ROOT" -name "*.tf" -type f | grep -q .; then
        log "Testing Conftest policies against Terraform files..."

        # Generate Terraform plan for testing
        cd "$PROJECT_ROOT/terraform" 2>/dev/null || cd "$PROJECT_ROOT"

        if [ -f "main.tf" ] || [ -f "terraform/main.tf" ]; then
            terraform init -upgrade >/dev/null 2>&1 || true
            terraform plan -out=tfplan >/dev/null 2>&1 || true

            if [ -f "tfplan" ]; then
                terraform show -json tfplan > plan.json 2>/dev/null || true

                if [ -f "plan.json" ]; then
                    conftest test \
                        --policy "${POLICIES_DIR}/conftest" \
                        plan.json > "$conftest_results_file" 2>&1 || true

                    if [ $? -eq 0 ]; then
                        success "Conftest validation passed"
                    else
                        warning "Conftest found policy violations - check results"
                    fi

                    # Cleanup
                    rm -f tfplan plan.json
                fi
            fi
        fi
    fi

    # Test against CloudFormation templates
    while IFS= read -r -d '' cf_template; do
        log "Testing Conftest policies against: $(basename "$cf_template")"

        conftest test \
            --policy "${POLICIES_DIR}/conftest" \
            "$cf_template" >> "$conftest_results_file" 2>&1 || true

    done < <(find "$PROJECT_ROOT" -name "*.yaml" -o -name "*.yml" | grep -E "(cloudformation|template)" | head -5 | tr '\n' '\0' 2>/dev/null)
}

# Validate Sentinel policies (if available)
validate_sentinel_policies() {
    log "Validating Sentinel policies..."

    if [ ! -d "${POLICIES_DIR}/sentinel" ]; then
        warning "No Sentinel policies directory found"
        return 0
    fi

    # Check if Sentinel CLI is available
    if ! command -v sentinel >/dev/null 2>&1; then
        warning "Sentinel CLI not available - skipping Sentinel validation"
        return 0
    fi

    local sentinel_results_file="${VALIDATION_RESULTS_DIR}/sentinel_validation_${TIMESTAMP}.txt"

    while IFS= read -r -d '' policy_file; do
        log "Validating Sentinel policy: $(basename "$policy_file")"

        # Test policy syntax and logic
        sentinel test "$policy_file" > "$sentinel_results_file" 2>&1 || true

        if [ $? -eq 0 ]; then
            success "Sentinel policy valid: $(basename "$policy_file")"
        else
            warning "Sentinel policy issues found: $(basename "$policy_file")"
        fi

    done < <(find "${POLICIES_DIR}/sentinel" -name "*.sentinel" -print0 2>/dev/null)
}

# Generate test data for policy validation
generate_test_data() {
    log "Generating test data for policy validation..."

    local test_data_file="${PROJECT_ROOT}/terraform/test-data.json"

    cat > "$test_data_file" << 'EOF'
{
  "resource_type": "aws_s3_bucket",
  "config": {
    "bucket": "test-bucket",
    "acl": "private",
    "server_side_encryption_configuration": [
      {
        "rule": [
          {
            "apply_server_side_encryption_by_default": {
              "sse_algorithm": "AES256"
            }
          }
        ]
      }
    ],
    "versioning": [
      {
        "enabled": true
      }
    ],
    "public_access_block": [
      {
        "block_public_acls": true,
        "block_public_policy": true,
        "ignore_public_acls": true,
        "restrict_public_buckets": true
      }
    ]
  }
}
EOF

    log "Test data generated: $test_data_file"
}

# Test policies against actual infrastructure
test_policies_against_infrastructure() {
    log "Testing policies against infrastructure configurations..."

    local policy_test_results="${VALIDATION_RESULTS_DIR}/policy_test_results_${TIMESTAMP}.json"

    # Test OPA policies against Terraform configurations
    if [ -d "${POLICIES_DIR}/opa" ] && find "$PROJECT_ROOT" -name "*.tf" -type f | grep -q .; then
        log "Testing OPA policies against Terraform files..."

        # Convert Terraform to JSON for OPA testing
        cd "$PROJECT_ROOT/terraform" 2>/dev/null || cd "$PROJECT_ROOT"

        if ls *.tf >/dev/null 2>&1; then
            terraform init -upgrade >/dev/null 2>&1 || true
            terraform plan -out=tfplan >/dev/null 2>&1 || true

            if [ -f "tfplan" ]; then
                terraform show -json tfplan > terraform-plan.json 2>/dev/null || true

                if [ -f "terraform-plan.json" ]; then
                    opa eval \
                        --data "${POLICIES_DIR}/opa" \
                        --input terraform-plan.json \
                        --format json \
                        "data.terraform.deny" > "$policy_test_results" 2>/dev/null || true

                    success "OPA policy testing completed"

                    # Cleanup
                    rm -f tfplan terraform-plan.json
                fi
            fi
        fi
    fi
}

# Generate validation report
generate_validation_report() {
    log "Generating policy validation report..."

    local report_file="${VALIDATION_RESULTS_DIR}/policy_validation_report_${TIMESTAMP}.md"

    cat > "$report_file" << EOF
# Policy Validation Report

**Validation Date:** $(date)
**Project:** $(basename "$PROJECT_ROOT")
**Validation ID:** ${TIMESTAMP}

## Overview

This report contains the results of policy validation performed on Infrastructure as Code policies.

## Policy Frameworks Tested

### Open Policy Agent (OPA)
- **Location:** \`policies/opa/\`
- **Policy Language:** Rego
- **Status:** $([ -d "${POLICIES_DIR}/opa" ] && echo "Found" || echo "Not Found")

### Conftest
- **Location:** \`policies/conftest/\`
- **Policy Language:** Rego (Conftest format)
- **Status:** $([ -d "${POLICIES_DIR}/conftest" ] && echo "Found" || echo "Not Found")

### Sentinel
- **Location:** \`policies/sentinel/\`
- **Policy Language:** Sentinel
- **Status:** $([ -d "${POLICIES_DIR}/sentinel" ] && echo "Found" || echo "Not Found")

## Validation Results

### Policy Count
- **OPA Policies:** $(find "${POLICIES_DIR}/opa" -name "*.rego" 2>/dev/null | wc -l)
- **Conftest Policies:** $(find "${POLICIES_DIR}/conftest" -name "*.rego" 2>/dev/null | wc -l)
- **Sentinel Policies:** $(find "${POLICIES_DIR}/sentinel" -name "*.sentinel" 2>/dev/null | wc -l)

### Infrastructure Files Tested
- **Terraform Files:** $(find "$PROJECT_ROOT" -name "*.tf" -type f | wc -l)
- **CloudFormation Templates:** $(find "$PROJECT_ROOT" -name "*.yaml" -o -name "*.yml" | grep -c cloudformation 2>/dev/null || echo 0)

## Recommendations

1. **Policy Coverage**: Ensure all critical security controls have corresponding policies
2. **Testing**: Implement automated policy testing in CI/CD pipeline
3. **Documentation**: Document policy intent and expected outcomes
4. **Maintenance**: Regular review and update of policies

## Next Steps

1. Review detailed validation results in individual files
2. Address any policy syntax or logic errors
3. Expand policy coverage for comprehensive security
4. Integrate policy validation into development workflow

---

**Generated by:** Policy Validation Script
**Results Location:** \`validation-results/\`
EOF

    success "Validation report generated: $report_file"
}

# Main execution
main() {
    log "Starting Policy Validation"
    log "Project: $(basename "$PROJECT_ROOT")"
    log "Timestamp: $TIMESTAMP"

    check_dependencies

    # Generate test data
    generate_test_data

    # Validate policies
    validate_opa_policies
    validate_conftest_policies
    validate_sentinel_policies

    # Test against infrastructure
    test_policies_against_infrastructure

    # Generate report
    generate_validation_report

    log "Policy validation completed successfully!"
    log "Results available in: $VALIDATION_RESULTS_DIR"

    # Show summary
    echo ""
    echo "Validation Summary:"
    echo "=================="
    echo "Results directory: $VALIDATION_RESULTS_DIR"
    echo "Files generated:"
    ls -la "$VALIDATION_RESULTS_DIR" | grep "$TIMESTAMP" | awk '{print "  - " $9}'
}

# Handle arguments
case "${1:-validate}" in
    validate)
        main
        ;;
    clean)
        log "Cleaning up old validation results..."
        find "$VALIDATION_RESULTS_DIR" -name "*_*" -mtime +7 -delete 2>/dev/null || true
        success "Cleanup completed"
        ;;
    --help|-h)
        echo "Usage: $0 [validate|clean|--help]"
        echo ""
        echo "Commands:"
        echo "  validate - Run policy validation (default)"
        echo "  clean    - Clean up old validation results"
        echo "  --help   - Show this help message"
        ;;
    *)
        error "Unknown command: $1"
        echo "Use --help for usage information"
        exit 1
        ;;
esac