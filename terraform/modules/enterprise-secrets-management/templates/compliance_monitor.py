#!/usr/bin/env python3
"""
Enterprise Secrets Compliance Monitor
Automated compliance monitoring and reporting for secrets management
"""

import json
import os
import boto3
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)


class SecretsComplianceMonitor:
    """Enterprise-grade compliance monitoring for secrets management"""

    def __init__(self):
        self.secrets_client = boto3.client('secretsmanager')
        self.sns_client = boto3.client('sns')
        self.cloudwatch = boto3.client('cloudwatch')
        self.sts_client = boto3.client('sts')

        # Environment configuration
        self.environment = os.environ.get('ENVIRONMENT', '${environment}')
        self.compliance_frameworks = os.environ.get('COMPLIANCE_FRAMEWORKS', '').split(',')
        self.notification_topic = os.environ.get('NOTIFICATION_TOPIC', '')
        self.strictest_rotation_days = int(os.environ.get('STRICTEST_ROTATION_DAYS', '90'))

        # Compliance framework requirements
        self.compliance_rules = {
            'SOC2': {
                'max_rotation_days': 90,
                'encryption_required': True,
                'access_logging_required': True,
                'version_control_required': True,
                'access_review_days': 30,
                'cross_region_backup': True
            },
            'PCI-DSS': {
                'max_rotation_days': 90,
                'encryption_required': True,
                'access_logging_required': True,
                'version_control_required': True,
                'access_review_days': 15,
                'cross_region_backup': True,
                'strong_authentication': True
            },
            'HIPAA': {
                'max_rotation_days': 60,
                'encryption_required': True,
                'access_logging_required': True,
                'version_control_required': True,
                'access_review_days': 30,
                'cross_region_backup': True,
                'data_integrity_checks': True
            },
            'NIST': {
                'max_rotation_days': 60,
                'encryption_required': True,
                'access_logging_required': True,
                'version_control_required': True,
                'access_review_days': 30,
                'incident_response_plan': True
            },
            'FIPS': {
                'max_rotation_days': 30,
                'encryption_required': True,
                'fips_140_2_level_2': True,
                'key_rotation_required': True,
                'access_review_days': 15,
                'cryptographic_modules': True
            }
        }

        # Secret categorization for compliance
        self.secret_categories = {
            'critical': {
                'max_age_days': 30,
                'rotation_required': True,
                'encryption_level': 'AES-256',
                'audit_frequency': 'daily'
            },
            'high': {
                'max_age_days': 60,
                'rotation_required': True,
                'encryption_level': 'AES-256',
                'audit_frequency': 'weekly'
            },
            'medium': {
                'max_age_days': 90,
                'rotation_required': True,
                'encryption_level': 'AES-256',
                'audit_frequency': 'monthly'
            },
            'low': {
                'max_age_days': 180,
                'rotation_required': False,
                'encryption_level': 'AES-128',
                'audit_frequency': 'quarterly'
            }
        }

    def lambda_handler(self, event: Dict[str, Any], context: Any) -> Dict[str, Any]:
        """Main Lambda handler for compliance monitoring"""
        try:
            check_type = event.get('check_type', 'full_compliance_audit')

            logger.info(f"Starting compliance check: {check_type}")

            if check_type == 'full_compliance_audit':
                result = self.perform_full_compliance_audit()
            elif check_type == 'rotation_compliance':
                result = self.check_rotation_compliance()
            elif check_type == 'access_compliance':
                result = self.check_access_compliance()
            elif check_type == 'encryption_compliance':
                result = self.check_encryption_compliance()
            elif check_type == 'lifecycle_compliance':
                result = self.check_lifecycle_compliance()
            else:
                raise ValueError(f"Unknown check type: {check_type}")

            # Generate compliance report
            compliance_report = self.generate_compliance_report(result)

            # Send notifications if violations found
            if result.get('violations'):
                self.send_compliance_notifications(compliance_report)

            # Update CloudWatch metrics
            self.update_compliance_metrics(result)

            return {
                'statusCode': 200,
                'body': json.dumps({
                    'success': True,
                    'check_type': check_type,
                    'compliance_score': result.get('compliance_score', 0),
                    'violations_count': len(result.get('violations', [])),
                    'report': compliance_report,
                    'timestamp': datetime.utcnow().isoformat()
                })
            }

        except Exception as e:
            logger.error(f"Compliance monitoring failed: {str(e)}")
            self.send_error_notification(str(e), event)

            return {
                'statusCode': 500,
                'body': json.dumps({
                    'success': False,
                    'error': str(e),
                    'timestamp': datetime.utcnow().isoformat()
                })
            }

    def perform_full_compliance_audit(self) -> Dict[str, Any]:
        """Perform comprehensive compliance audit"""
        logger.info("Performing full compliance audit")

        audit_results = {
            'rotation_compliance': self.check_rotation_compliance(),
            'access_compliance': self.check_access_compliance(),
            'encryption_compliance': self.check_encryption_compliance(),
            'lifecycle_compliance': self.check_lifecycle_compliance(),
            'framework_compliance': self.check_framework_compliance()
        }

        # Aggregate results
        total_checks = 0
        passed_checks = 0
        all_violations = []

        for check_type, result in audit_results.items():
            total_checks += result.get('total_checks', 0)
            passed_checks += result.get('passed_checks', 0)
            all_violations.extend(result.get('violations', []))

        compliance_score = (passed_checks / total_checks * 100) if total_checks > 0 else 0

        return {
            'audit_type': 'full_compliance_audit',
            'total_checks': total_checks,
            'passed_checks': passed_checks,
            'compliance_score': compliance_score,
            'violations': all_violations,
            'detailed_results': audit_results,
            'audit_timestamp': datetime.utcnow().isoformat()
        }

    def check_rotation_compliance(self) -> Dict[str, Any]:
        """Check secret rotation compliance"""
        logger.info("Checking rotation compliance")

        violations = []
        total_secrets = 0
        compliant_secrets = 0

        try:
            # Get all secrets
            paginator = self.secrets_client.get_paginator('list_secrets')

            for page in paginator.paginate():
                for secret in page['SecretList']:
                    total_secrets += 1
                    secret_arn = secret['ARN']
                    secret_name = secret['Name']

                    # Get secret metadata
                    secret_metadata = self.get_secret_metadata(secret_arn)
                    category = secret_metadata.get('category', 'medium')

                    # Check rotation configuration
                    rotation_enabled = secret.get('RotationEnabled', False)
                    rotation_rules = secret.get('RotationRules', {})

                    if not rotation_enabled and self.secret_categories[category]['rotation_required']:
                        violations.append({
                            'type': 'rotation_not_enabled',
                            'secret_name': secret_name,
                            'secret_arn': secret_arn,
                            'category': category,
                            'severity': 'high',
                            'description': f"Rotation not enabled for {category} category secret"
                        })
                        continue

                    if rotation_enabled:
                        rotation_days = rotation_rules.get('AutomaticallyAfterDays', 0)
                        max_allowed = min(
                            self.secret_categories[category]['max_age_days'],
                            self.strictest_rotation_days
                        )

                        if rotation_days > max_allowed:
                            violations.append({
                                'type': 'rotation_interval_too_long',
                                'secret_name': secret_name,
                                'secret_arn': secret_arn,
                                'category': category,
                                'current_interval': rotation_days,
                                'max_allowed': max_allowed,
                                'severity': 'medium',
                                'description': f"Rotation interval ({rotation_days} days) exceeds maximum allowed ({max_allowed} days)"
                            })
                            continue

                    # Check last rotation date
                    last_rotation = secret.get('LastRotatedDate')
                    if last_rotation:
                        days_since_rotation = (datetime.utcnow() - last_rotation.replace(tzinfo=None)).days
                        max_age = self.secret_categories[category]['max_age_days']

                        if days_since_rotation > max_age:
                            violations.append({
                                'type': 'secret_overdue_rotation',
                                'secret_name': secret_name,
                                'secret_arn': secret_arn,
                                'category': category,
                                'days_since_rotation': days_since_rotation,
                                'max_age': max_age,
                                'severity': 'high',
                                'description': f"Secret overdue for rotation ({days_since_rotation} days old)"
                            })
                            continue

                    compliant_secrets += 1

        except ClientError as e:
            logger.error(f"Failed to check rotation compliance: {e}")
            violations.append({
                'type': 'audit_error',
                'description': f"Failed to audit rotation compliance: {str(e)}",
                'severity': 'critical'
            })

        return {
            'check_type': 'rotation_compliance',
            'total_checks': total_secrets,
            'passed_checks': compliant_secrets,
            'violations': violations,
            'compliance_percentage': (compliant_secrets / total_secrets * 100) if total_secrets > 0 else 0
        }

    def check_access_compliance(self) -> Dict[str, Any]:
        """Check access control compliance"""
        logger.info("Checking access compliance")

        violations = []
        total_checks = 0
        passed_checks = 0

        try:
            # Get account ID for policy analysis
            account_id = self.sts_client.get_caller_identity()['Account']

            # Get all secrets
            paginator = self.secrets_client.get_paginator('list_secrets')

            for page in paginator.paginate():
                for secret in page['SecretList']:
                    total_checks += 1
                    secret_arn = secret['ARN']
                    secret_name = secret['Name']

                    # Check resource policy
                    try:
                        policy_response = self.secrets_client.get_resource_policy(SecretId=secret_arn)
                        resource_policy = policy_response.get('ResourcePolicy')

                        if resource_policy:
                            policy_analysis = self.analyze_secret_policy(resource_policy, account_id)

                            if policy_analysis.get('violations'):
                                violations.extend([
                                    {**violation, 'secret_name': secret_name, 'secret_arn': secret_arn}
                                    for violation in policy_analysis['violations']
                                ])
                                continue

                    except ClientError as e:
                        if e.response['Error']['Code'] != 'ResourceNotFoundException':
                            logger.warning(f"Failed to get resource policy for {secret_name}: {e}")

                    # Check secret metadata for access control
                    secret_metadata = self.get_secret_metadata(secret_arn)
                    category = secret_metadata.get('category', 'medium')

                    # Verify encryption is enabled
                    kms_key_id = secret.get('KmsKeyId')
                    if not kms_key_id:
                        violations.append({
                            'type': 'encryption_not_enabled',
                            'secret_name': secret_name,
                            'secret_arn': secret_arn,
                            'category': category,
                            'severity': 'high',
                            'description': "Secret not encrypted with customer-managed KMS key"
                        })
                        continue

                    passed_checks += 1

        except Exception as e:
            logger.error(f"Failed to check access compliance: {e}")
            violations.append({
                'type': 'audit_error',
                'description': f"Failed to audit access compliance: {str(e)}",
                'severity': 'critical'
            })

        return {
            'check_type': 'access_compliance',
            'total_checks': total_checks,
            'passed_checks': passed_checks,
            'violations': violations,
            'compliance_percentage': (passed_checks / total_checks * 100) if total_checks > 0 else 0
        }

    def check_encryption_compliance(self) -> Dict[str, Any]:
        """Check encryption compliance"""
        logger.info("Checking encryption compliance")

        violations = []
        total_checks = 0
        passed_checks = 0

        try:
            # Get all secrets
            paginator = self.secrets_client.get_paginator('list_secrets')

            for page in paginator.paginate():
                for secret in page['SecretList']:
                    total_checks += 1
                    secret_arn = secret['ARN']
                    secret_name = secret['Name']

                    # Check KMS encryption
                    kms_key_id = secret.get('KmsKeyId')

                    if not kms_key_id:
                        violations.append({
                            'type': 'no_customer_managed_key',
                            'secret_name': secret_name,
                            'secret_arn': secret_arn,
                            'severity': 'high',
                            'description': "Secret using default AWS managed key instead of customer-managed key"
                        })
                        continue

                    # Check if using default AWS managed key
                    if kms_key_id == 'alias/aws/secretsmanager':
                        violations.append({
                            'type': 'using_aws_managed_key',
                            'secret_name': secret_name,
                            'secret_arn': secret_arn,
                            'severity': 'medium',
                            'description': "Secret using AWS managed key instead of customer-managed key"
                        })
                        continue

                    # Verify KMS key properties
                    key_compliance = self.check_kms_key_compliance(kms_key_id)

                    if not key_compliance['compliant']:
                        violations.extend([
                            {**violation, 'secret_name': secret_name, 'secret_arn': secret_arn}
                            for violation in key_compliance['violations']
                        ])
                        continue

                    passed_checks += 1

        except Exception as e:
            logger.error(f"Failed to check encryption compliance: {e}")
            violations.append({
                'type': 'audit_error',
                'description': f"Failed to audit encryption compliance: {str(e)}",
                'severity': 'critical'
            })

        return {
            'check_type': 'encryption_compliance',
            'total_checks': total_checks,
            'passed_checks': passed_checks,
            'violations': violations,
            'compliance_percentage': (passed_checks / total_checks * 100) if total_checks > 0 else 0
        }

    def check_lifecycle_compliance(self) -> Dict[str, Any]:
        """Check secret lifecycle compliance"""
        logger.info("Checking lifecycle compliance")

        violations = []
        total_checks = 0
        passed_checks = 0

        try:
            # Get all secrets
            paginator = self.secrets_client.get_paginator('list_secrets')

            for page in paginator.paginate():
                for secret in page['SecretList']:
                    total_checks += 1
                    secret_arn = secret['ARN']
                    secret_name = secret['Name']

                    # Check version management
                    try:
                        secret_detail = self.secrets_client.describe_secret(SecretId=secret_arn)
                        versions = secret_detail.get('VersionIdsToStages', {})

                        # Check for proper version stages
                        has_current = any('AWSCURRENT' in stages for stages in versions.values())
                        has_pending = any('AWSPENDING' in stages for stages in versions.values())

                        if not has_current:
                            violations.append({
                                'type': 'no_current_version',
                                'secret_name': secret_name,
                                'secret_arn': secret_arn,
                                'severity': 'critical',
                                'description': "Secret has no AWSCURRENT version"
                            })
                            continue

                        # Check version count (too many versions can indicate cleanup issues)
                        if len(versions) > 10:
                            violations.append({
                                'type': 'too_many_versions',
                                'secret_name': secret_name,
                                'secret_arn': secret_arn,
                                'version_count': len(versions),
                                'severity': 'low',
                                'description': f"Secret has {len(versions)} versions (cleanup recommended)"
                            })

                        # Check for stuck pending rotations
                        if has_pending:
                            # Check if pending version is old (indicates failed rotation)
                            pending_version_id = None
                            for version_id, stages in versions.items():
                                if 'AWSPENDING' in stages:
                                    pending_version_id = version_id
                                    break

                            if pending_version_id:
                                # In a real implementation, you'd check the version creation date
                                # This is a simplified check
                                violations.append({
                                    'type': 'stuck_pending_rotation',
                                    'secret_name': secret_name,
                                    'secret_arn': secret_arn,
                                    'pending_version': pending_version_id,
                                    'severity': 'medium',
                                    'description': "Secret has pending rotation that may be stuck"
                                })

                    except ClientError as e:
                        logger.warning(f"Failed to check versions for {secret_name}: {e}")
                        violations.append({
                            'type': 'version_check_failed',
                            'secret_name': secret_name,
                            'secret_arn': secret_arn,
                            'error': str(e),
                            'severity': 'medium',
                            'description': "Failed to verify secret versions"
                        })
                        continue

                    passed_checks += 1

        except Exception as e:
            logger.error(f"Failed to check lifecycle compliance: {e}")
            violations.append({
                'type': 'audit_error',
                'description': f"Failed to audit lifecycle compliance: {str(e)}",
                'severity': 'critical'
            })

        return {
            'check_type': 'lifecycle_compliance',
            'total_checks': total_checks,
            'passed_checks': passed_checks,
            'violations': violations,
            'compliance_percentage': (passed_checks / total_checks * 100) if total_checks > 0 else 0
        }

    def check_framework_compliance(self) -> Dict[str, Any]:
        """Check compliance against specific frameworks"""
        logger.info(f"Checking framework compliance for: {self.compliance_frameworks}")

        framework_results = {}
        all_violations = []

        for framework in self.compliance_frameworks:
            if framework not in self.compliance_rules:
                continue

            framework_violations = []
            rules = self.compliance_rules[framework]

            # Check framework-specific requirements
            if rules.get('max_rotation_days'):
                if self.strictest_rotation_days > rules['max_rotation_days']:
                    framework_violations.append({
                        'type': 'rotation_interval_violation',
                        'framework': framework,
                        'current_max': self.strictest_rotation_days,
                        'required_max': rules['max_rotation_days'],
                        'severity': 'high',
                        'description': f"{framework} requires rotation every {rules['max_rotation_days']} days or less"
                    })

            # Check encryption requirements
            if rules.get('encryption_required'):
                encryption_check = self.verify_framework_encryption_requirements(framework, rules)
                framework_violations.extend(encryption_check)

            # Check access logging requirements
            if rules.get('access_logging_required'):
                logging_check = self.verify_access_logging_requirements(framework)
                framework_violations.extend(logging_check)

            framework_results[framework] = {
                'violations': framework_violations,
                'compliant': len(framework_violations) == 0
            }

            all_violations.extend(framework_violations)

        return {
            'check_type': 'framework_compliance',
            'frameworks_checked': self.compliance_frameworks,
            'framework_results': framework_results,
            'violations': all_violations,
            'overall_compliance': len(all_violations) == 0
        }

    def get_secret_metadata(self, secret_arn: str) -> Dict[str, Any]:
        """Get secret metadata from tags"""
        try:
            response = self.secrets_client.describe_secret(SecretId=secret_arn)
            tags = response.get('Tags', [])

            metadata = {
                'category': 'medium',  # default
                'secret_type': 'unknown'
            }

            for tag in tags:
                if tag['Key'] == 'Category':
                    metadata['category'] = tag['Value']
                elif tag['Key'] == 'SecretType':
                    metadata['secret_type'] = tag['Value']

            return metadata

        except ClientError:
            return {'category': 'medium', 'secret_type': 'unknown'}

    def analyze_secret_policy(self, policy_json: str, account_id: str) -> Dict[str, Any]:
        """Analyze secret resource policy for compliance violations"""
        violations = []

        try:
            policy = json.loads(policy_json)

            for statement in policy.get('Statement', []):
                effect = statement.get('Effect', 'Deny')
                principals = statement.get('Principal', {})

                # Check for overly permissive policies
                if effect == 'Allow':
                    if principals == '*' or 'AWS' in principals and principals['AWS'] == '*':
                        violations.append({
                            'type': 'overly_permissive_policy',
                            'severity': 'high',
                            'description': "Secret policy allows access from any principal (*)"
                        })

                    # Check for cross-account access without conditions
                    if 'AWS' in principals:
                        aws_principals = principals['AWS'] if isinstance(principals['AWS'], list) else [principals['AWS']]
                        for principal in aws_principals:
                            if ':' in principal and not principal.startswith(f'arn:aws:iam::{account_id}:'):
                                conditions = statement.get('Condition', {})
                                if not conditions:
                                    violations.append({
                                        'type': 'cross_account_without_conditions',
                                        'principal': principal,
                                        'severity': 'medium',
                                        'description': f"Cross-account access granted without conditions to {principal}"
                                    })

        except json.JSONDecodeError:
            violations.append({
                'type': 'invalid_policy_format',
                'severity': 'medium',
                'description': "Secret resource policy is not valid JSON"
            })

        return {
            'violations': violations,
            'compliant': len(violations) == 0
        }

    def check_kms_key_compliance(self, kms_key_id: str) -> Dict[str, Any]:
        """Check KMS key compliance"""
        violations = []

        try:
            kms_client = boto3.client('kms')

            # Get key details
            key_response = kms_client.describe_key(KeyId=kms_key_id)
            key_metadata = key_response['KeyMetadata']

            # Check key rotation
            if not kms_client.get_key_rotation_status(KeyId=kms_key_id)['KeyRotationEnabled']:
                violations.append({
                    'type': 'key_rotation_disabled',
                    'kms_key_id': kms_key_id,
                    'severity': 'medium',
                    'description': "KMS key rotation is not enabled"
                })

            # Check key usage
            key_usage = key_metadata.get('KeyUsage', '')
            if key_usage != 'ENCRYPT_DECRYPT':
                violations.append({
                    'type': 'incorrect_key_usage',
                    'kms_key_id': kms_key_id,
                    'current_usage': key_usage,
                    'severity': 'high',
                    'description': f"KMS key usage is {key_usage}, should be ENCRYPT_DECRYPT"
                })

        except ClientError as e:
            violations.append({
                'type': 'kms_key_check_failed',
                'kms_key_id': kms_key_id,
                'error': str(e),
                'severity': 'medium',
                'description': f"Failed to verify KMS key compliance: {str(e)}"
            })

        return {
            'violations': violations,
            'compliant': len(violations) == 0
        }

    def verify_framework_encryption_requirements(self, framework: str, rules: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Verify encryption requirements for specific framework"""
        violations = []

        # Framework-specific encryption checks
        if framework == 'FIPS' and rules.get('fips_140_2_level_2'):
            # In a real implementation, you'd verify FIPS 140-2 Level 2 compliance
            violations.append({
                'type': 'fips_compliance_check_needed',
                'framework': framework,
                'severity': 'medium',
                'description': "FIPS 140-2 Level 2 compliance verification required"
            })

        return violations

    def verify_access_logging_requirements(self, framework: str) -> List[Dict[str, Any]]:
        """Verify access logging requirements"""
        violations = []

        # Check CloudTrail configuration for secrets access logging
        try:
            cloudtrail = boto3.client('cloudtrail')
            trails = cloudtrail.describe_trails()

            secrets_logging_enabled = False
            for trail in trails['trailList']:
                if trail.get('IncludeGlobalServiceEvents', False):
                    # Check if trail is active and logging data events
                    trail_status = cloudtrail.get_trail_status(Name=trail['TrailARN'])
                    if trail_status.get('IsLogging', False):
                        secrets_logging_enabled = True
                        break

            if not secrets_logging_enabled:
                violations.append({
                    'type': 'access_logging_not_configured',
                    'framework': framework,
                    'severity': 'high',
                    'description': f"{framework} requires access logging to be enabled via CloudTrail"
                })

        except ClientError as e:
            violations.append({
                'type': 'logging_check_failed',
                'framework': framework,
                'error': str(e),
                'severity': 'medium',
                'description': f"Failed to verify access logging for {framework}: {str(e)}"
            })

        return violations

    def generate_compliance_report(self, audit_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive compliance report"""
        return {
            'report_id': f"compliance-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
            'environment': self.environment,
            'compliance_frameworks': self.compliance_frameworks,
            'audit_timestamp': datetime.utcnow().isoformat(),
            'summary': {
                'overall_score': audit_results.get('compliance_score', 0),
                'total_violations': len(audit_results.get('violations', [])),
                'critical_violations': len([v for v in audit_results.get('violations', []) if v.get('severity') == 'critical']),
                'high_violations': len([v for v in audit_results.get('violations', []) if v.get('severity') == 'high']),
                'medium_violations': len([v for v in audit_results.get('violations', []) if v.get('severity') == 'medium']),
                'low_violations': len([v for v in audit_results.get('violations', []) if v.get('severity') == 'low'])
            },
            'detailed_results': audit_results,
            'recommendations': self.generate_remediation_recommendations(audit_results.get('violations', []))
        }

    def generate_remediation_recommendations(self, violations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate remediation recommendations for violations"""
        recommendations = []

        violation_types = {}
        for violation in violations:
            violation_type = violation.get('type', 'unknown')
            if violation_type not in violation_types:
                violation_types[violation_type] = []
            violation_types[violation_type].append(violation)

        for violation_type, instances in violation_types.items():
            if violation_type == 'rotation_not_enabled':
                recommendations.append({
                    'violation_type': violation_type,
                    'count': len(instances),
                    'priority': 'high',
                    'action': 'Enable automatic rotation for all secrets requiring rotation',
                    'implementation': 'Update Terraform configuration to set enable_automatic_rotation = true'
                })
            elif violation_type == 'encryption_not_enabled':
                recommendations.append({
                    'violation_type': violation_type,
                    'count': len(instances),
                    'priority': 'critical',
                    'action': 'Configure customer-managed KMS keys for all secrets',
                    'implementation': 'Create KMS keys and update secret configurations'
                })
            elif violation_type == 'overly_permissive_policy':
                recommendations.append({
                    'violation_type': violation_type,
                    'count': len(instances),
                    'priority': 'high',
                    'action': 'Implement principle of least privilege in secret policies',
                    'implementation': 'Review and restrict secret resource policies'
                })

        return recommendations

    def send_compliance_notifications(self, report: Dict[str, Any]) -> None:
        """Send compliance violation notifications"""
        if not self.notification_topic:
            logger.warning("No notification topic configured")
            return

        try:
            summary = report['summary']
            critical_count = summary['critical_violations']
            high_count = summary['high_violations']

            if critical_count > 0 or high_count > 0:
                subject = f"URGENT: Secrets Compliance Violations Detected - {self.environment}"
                priority = "CRITICAL" if critical_count > 0 else "HIGH"
            else:
                subject = f"Secrets Compliance Report - {self.environment}"
                priority = "MEDIUM"

            message = f"""
Secrets Management Compliance Report

Environment: {self.environment}
Report ID: {report['report_id']}
Audit Time: {report['audit_timestamp']}
Overall Score: {summary['overall_score']:.1f}%

Violation Summary:
- Critical: {critical_count}
- High: {high_count}
- Medium: {summary['medium_violations']}
- Low: {summary['low_violations']}

Compliance Frameworks: {', '.join(self.compliance_frameworks)}

{"IMMEDIATE ACTION REQUIRED" if critical_count > 0 else "Review and remediation recommended"}

Full report details available in CloudWatch logs.
"""

            self.sns_client.publish(
                TopicArn=self.notification_topic,
                Message=message,
                Subject=subject
            )

            logger.info(f"Compliance notification sent with priority {priority}")

        except ClientError as e:
            logger.error(f"Failed to send compliance notification: {e}")

    def send_error_notification(self, error_message: str, event: Dict[str, Any]) -> None:
        """Send error notification"""
        if not self.notification_topic:
            return

        try:
            message = f"""
Secrets Compliance Monitoring Error

Environment: {self.environment}
Error: {error_message}
Event: {json.dumps(event, default=str)}
Timestamp: {datetime.utcnow().isoformat()}

Please investigate and resolve the compliance monitoring issue.
"""

            self.sns_client.publish(
                TopicArn=self.notification_topic,
                Message=message,
                Subject=f"Secrets Compliance Monitoring Error - {self.environment}"
            )

        except ClientError as e:
            logger.error(f"Failed to send error notification: {e}")

    def update_compliance_metrics(self, results: Dict[str, Any]) -> None:
        """Update CloudWatch metrics for compliance monitoring"""
        try:
            metrics = [
                {
                    'MetricName': 'ComplianceScore',
                    'Dimensions': [
                        {'Name': 'Environment', 'Value': self.environment}
                    ],
                    'Value': results.get('compliance_score', 0),
                    'Unit': 'Percent'
                },
                {
                    'MetricName': 'ComplianceViolations',
                    'Dimensions': [
                        {'Name': 'Environment', 'Value': self.environment},
                        {'Name': 'Severity', 'Value': 'Critical'}
                    ],
                    'Value': len([v for v in results.get('violations', []) if v.get('severity') == 'critical']),
                    'Unit': 'Count'
                },
                {
                    'MetricName': 'ComplianceViolations',
                    'Dimensions': [
                        {'Name': 'Environment', 'Value': self.environment},
                        {'Name': 'Severity', 'Value': 'High'}
                    ],
                    'Value': len([v for v in results.get('violations', []) if v.get('severity') == 'high']),
                    'Unit': 'Count'
                }
            ]

            self.cloudwatch.put_metric_data(
                Namespace=f'SecretsCompliance/{self.environment}',
                MetricData=metrics
            )

            logger.info("Updated compliance CloudWatch metrics")

        except ClientError as e:
            logger.error(f"Failed to update CloudWatch metrics: {e}")


# Global monitor instance
compliance_monitor = SecretsComplianceMonitor()


def lambda_handler(event, context):
    """AWS Lambda entry point"""
    return compliance_monitor.lambda_handler(event, context)