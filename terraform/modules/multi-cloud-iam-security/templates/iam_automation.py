#!/usr/bin/env python3
"""
Multi-Cloud IAM Automation Lambda Function
Enterprise-grade automation for identity and access management across cloud providers
"""

import json
import boto3
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import os
import re

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients
sso_admin_client = boto3.client('sso-admin')
organizations_client = boto3.client('organizations')
iam_client = boto3.client('iam')

# Configuration
SSO_INSTANCE_ARN = os.environ.get('SSO_INSTANCE_ARN', '${sso_instance_arn}')
ENVIRONMENT = os.environ.get('ENVIRONMENT', 'prod')

class IAMAutomation:
    """Multi-cloud IAM automation and governance"""

    def __init__(self):
        self.sso_instance_arn = SSO_INSTANCE_ARN
        self.environment = ENVIRONMENT

    def audit_permission_sets(self) -> Dict[str, Any]:
        """Audit AWS SSO permission sets for compliance"""
        try:
            logger.info("Starting permission sets audit")

            # List all permission sets
            response = sso_admin_client.list_permission_sets(
                InstanceArn=self.sso_instance_arn
            )

            audit_results = {
                'total_permission_sets': len(response['PermissionSets']),
                'compliant_sets': 0,
                'non_compliant_sets': 0,
                'violations': [],
                'recommendations': []
            }

            for ps_arn in response['PermissionSets']:
                ps_details = sso_admin_client.describe_permission_set(
                    InstanceArn=self.sso_instance_arn,
                    PermissionSetArn=ps_arn
                )

                ps_name = ps_details['PermissionSet']['Name']
                session_duration = ps_details['PermissionSet'].get('SessionDuration', 'PT1H')

                # Check session duration compliance
                if self._parse_duration(session_duration) > 3600:  # 1 hour
                    audit_results['violations'].append({
                        'permission_set': ps_name,
                        'violation': 'Session duration exceeds 1 hour',
                        'current_value': session_duration,
                        'recommended_value': 'PT1H'
                    })
                    audit_results['non_compliant_sets'] += 1
                else:
                    audit_results['compliant_sets'] += 1

                # Check for overly permissive policies
                self._audit_permission_set_policies(ps_arn, ps_name, audit_results)

            # Generate recommendations
            if audit_results['violations']:
                audit_results['recommendations'].extend([
                    "Reduce session duration to 1 hour or less for enhanced security",
                    "Review and minimize permissions following principle of least privilege",
                    "Implement regular access reviews and certifications"
                ])

            logger.info(f"Permission sets audit completed: {audit_results['compliant_sets']} compliant, {audit_results['non_compliant_sets']} non-compliant")
            return audit_results

        except Exception as e:
            logger.error(f"Error auditing permission sets: {str(e)}")
            return {'error': str(e)}

    def _audit_permission_set_policies(self, ps_arn: str, ps_name: str, audit_results: Dict[str, Any]):
        """Audit policies attached to permission set"""
        try:
            # Check managed policies
            managed_policies = sso_admin_client.list_managed_policies_in_permission_set(
                InstanceArn=self.sso_instance_arn,
                PermissionSetArn=ps_arn
            )

            risky_policies = [
                'arn:aws:iam::aws:policy/AdministratorAccess',
                'arn:aws:iam::aws:policy/PowerUserAccess'
            ]

            for policy_arn in managed_policies['AttachedManagedPolicies']:
                if policy_arn in risky_policies and not ps_name.lower().startswith('admin'):
                    audit_results['violations'].append({
                        'permission_set': ps_name,
                        'violation': f'High-privilege policy attached to non-admin role: {policy_arn}',
                        'recommendation': 'Use more specific policies or custom policies with minimal permissions'
                    })

            # Check inline policies
            try:
                inline_policy = sso_admin_client.get_inline_policy_for_permission_set(
                    InstanceArn=self.sso_instance_arn,
                    PermissionSetArn=ps_arn
                )

                if inline_policy.get('InlinePolicy'):
                    policy_doc = json.loads(inline_policy['InlinePolicy'])
                    self._audit_policy_document(policy_doc, ps_name, audit_results)

            except sso_admin_client.exceptions.ResourceNotFoundException:
                # No inline policy exists
                pass

        except Exception as e:
            logger.warning(f"Error auditing policies for {ps_name}: {str(e)}")

    def _audit_policy_document(self, policy_doc: Dict[str, Any], ps_name: str, audit_results: Dict[str, Any]):
        """Audit individual policy document for security issues"""
        try:
            statements = policy_doc.get('Statement', [])
            if not isinstance(statements, list):
                statements = [statements]

            for statement in statements:
                effect = statement.get('Effect', 'Deny')
                actions = statement.get('Action', [])
                resources = statement.get('Resource', [])

                if not isinstance(actions, list):
                    actions = [actions]
                if not isinstance(resources, list):
                    resources = [resources]

                # Check for overly broad permissions
                if effect == 'Allow':
                    for action in actions:
                        if action == '*' or action.endswith(':*'):
                            for resource in resources:
                                if resource == '*':
                                    audit_results['violations'].append({
                                        'permission_set': ps_name,
                                        'violation': f'Overly broad permissions: Action "{action}" on Resource "{resource}"',
                                        'recommendation': 'Specify explicit actions and resources'
                                    })

        except Exception as e:
            logger.warning(f"Error auditing policy document for {ps_name}: {str(e)}")

    def cleanup_unused_resources(self) -> Dict[str, Any]:
        """Clean up unused IAM resources"""
        try:
            logger.info("Starting IAM resource cleanup")

            cleanup_results = {
                'unused_roles': [],
                'unused_policies': [],
                'unused_users': [],
                'actions_taken': [],
                'recommendations': []
            }

            # Find unused IAM roles
            self._find_unused_roles(cleanup_results)

            # Find unused customer managed policies
            self._find_unused_policies(cleanup_results)

            # Find unused IAM users (in environments where SSO should be used)
            if self.environment == 'prod':
                self._find_unused_users(cleanup_results)

            logger.info(f"IAM cleanup completed: {len(cleanup_results['actions_taken'])} actions taken")
            return cleanup_results

        except Exception as e:
            logger.error(f"Error during IAM cleanup: {str(e)}")
            return {'error': str(e)}

    def _find_unused_roles(self, cleanup_results: Dict[str, Any]):
        """Find and optionally remove unused IAM roles"""
        try:
            paginator = iam_client.get_paginator('list_roles')

            for page in paginator.paginate():
                for role in page['Roles']:
                    role_name = role['RoleName']

                    # Skip AWS service roles and system roles
                    if (role_name.startswith('AWS') or
                        role_name.startswith('aws-') or
                        'AWSServiceRole' in role_name):
                        continue

                    # Check if role has been used recently
                    last_used = self._get_role_last_used(role_name)
                    if last_used and (datetime.utcnow() - last_used).days > 90:
                        cleanup_results['unused_roles'].append({
                            'role_name': role_name,
                            'last_used': last_used.isoformat() if last_used else 'Never',
                            'created_date': role['CreateDate'].isoformat(),
                            'action': 'Flagged for review'
                        })

                        cleanup_results['recommendations'].append(
                            f"Review role {role_name} - unused for 90+ days"
                        )

        except Exception as e:
            logger.warning(f"Error finding unused roles: {str(e)}")

    def _find_unused_policies(self, cleanup_results: Dict[str, Any]):
        """Find unused customer managed policies"""
        try:
            paginator = iam_client.get_paginator('list_policies')

            for page in paginator.paginate(Scope='Local'):  # Customer managed policies only
                for policy in page['Policies']:
                    if policy['AttachmentCount'] == 0:
                        cleanup_results['unused_policies'].append({
                            'policy_name': policy['PolicyName'],
                            'policy_arn': policy['Arn'],
                            'created_date': policy['CreateDate'].isoformat(),
                            'attachment_count': policy['AttachmentCount'],
                            'action': 'Flagged for deletion'
                        })

                        cleanup_results['recommendations'].append(
                            f"Consider deleting unused policy: {policy['PolicyName']}"
                        )

        except Exception as e:
            logger.warning(f"Error finding unused policies: {str(e)}")

    def _find_unused_users(self, cleanup_results: Dict[str, Any]):
        """Find unused IAM users (should use SSO instead)"""
        try:
            paginator = iam_client.get_paginator('list_users')

            for page in paginator.paginate():
                for user in page['Users']:
                    user_name = user['UserName']

                    # Skip service accounts and system users
                    if (user_name.startswith('svc-') or
                        user_name.startswith('system-') or
                        user_name.endswith('-service')):
                        continue

                    # Check last activity
                    last_used = user.get('PasswordLastUsed')
                    if not last_used or (datetime.utcnow() - last_used.replace(tzinfo=None)).days > 60:
                        cleanup_results['unused_users'].append({
                            'user_name': user_name,
                            'last_used': last_used.isoformat() if last_used else 'Never',
                            'created_date': user['CreateDate'].isoformat(),
                            'recommendation': 'Migrate to SSO or disable if unused'
                        })

        except Exception as e:
            logger.warning(f"Error finding unused users: {str(e)}")

    def _get_role_last_used(self, role_name: str) -> Optional[datetime]:
        """Get the last used date for an IAM role"""
        try:
            response = iam_client.get_role(RoleName=role_name)
            role_last_used = response['Role'].get('RoleLastUsed')

            if role_last_used and 'LastUsedDate' in role_last_used:
                return role_last_used['LastUsedDate'].replace(tzinfo=None)

            return None

        except Exception as e:
            logger.warning(f"Error getting last used date for role {role_name}: {str(e)}")
            return None

    def enforce_compliance_policies(self) -> Dict[str, Any]:
        """Enforce compliance policies across IAM resources"""
        try:
            logger.info("Starting compliance policy enforcement")

            enforcement_results = {
                'policies_enforced': 0,
                'violations_found': 0,
                'remediation_actions': [],
                'compliance_score': 0
            }

            # Enforce session duration limits
            self._enforce_session_duration_limits(enforcement_results)

            # Enforce MFA requirements
            self._enforce_mfa_requirements(enforcement_results)

            # Enforce password policies
            self._enforce_password_policies(enforcement_results)

            # Calculate compliance score
            total_checks = 10  # Total number of compliance checks
            enforcement_results['compliance_score'] = max(0,
                100 - (enforcement_results['violations_found'] * 100 / total_checks))

            logger.info(f"Compliance enforcement completed. Score: {enforcement_results['compliance_score']}")
            return enforcement_results

        except Exception as e:
            logger.error(f"Error enforcing compliance policies: {str(e)}")
            return {'error': str(e)}

    def _enforce_session_duration_limits(self, results: Dict[str, Any]):
        """Enforce session duration limits on permission sets"""
        try:
            response = sso_admin_client.list_permission_sets(
                InstanceArn=self.sso_instance_arn
            )

            for ps_arn in response['PermissionSets']:
                ps_details = sso_admin_client.describe_permission_set(
                    InstanceArn=self.sso_instance_arn,
                    PermissionSetArn=ps_arn
                )

                current_duration = ps_details['PermissionSet'].get('SessionDuration', 'PT1H')
                if self._parse_duration(current_duration) > 3600:
                    results['violations_found'] += 1
                    results['remediation_actions'].append(
                        f"Permission set {ps_details['PermissionSet']['Name']} has excessive session duration"
                    )

        except Exception as e:
            logger.warning(f"Error enforcing session duration limits: {str(e)}")

    def _enforce_mfa_requirements(self, results: Dict[str, Any]):
        """Check and enforce MFA requirements"""
        try:
            # This would typically integrate with identity provider APIs
            # For now, we'll check if MFA policies are in place

            try:
                # Check if there's an MFA policy attached to roles
                paginator = iam_client.get_paginator('list_roles')
                mfa_protected_roles = 0
                total_roles = 0

                for page in paginator.paginate():
                    for role in page['Roles']:
                        if not role['RoleName'].startswith('AWS'):
                            total_roles += 1

                            # Check if role has MFA condition in trust policy
                            trust_policy = role['AssumeRolePolicyDocument']
                            if 'aws:MultiFactorAuthPresent' in str(trust_policy):
                                mfa_protected_roles += 1

                if total_roles > 0:
                    mfa_coverage = (mfa_protected_roles / total_roles) * 100
                    if mfa_coverage < 90:  # 90% coverage required
                        results['violations_found'] += 1
                        results['remediation_actions'].append(
                            f"MFA coverage is only {mfa_coverage:.1f}% - should be 90% or higher"
                        )

            except Exception as e:
                logger.warning(f"Error checking MFA requirements: {str(e)}")

        except Exception as e:
            logger.warning(f"Error enforcing MFA requirements: {str(e)}")

    def _enforce_password_policies(self, results: Dict[str, Any]):
        """Enforce password policies for IAM users"""
        try:
            password_policy = iam_client.get_account_password_policy()
            policy = password_policy['PasswordPolicy']

            violations = []

            if policy.get('MinimumPasswordLength', 0) < 14:
                violations.append("Password minimum length should be 14 characters")

            if not policy.get('RequireSymbols', False):
                violations.append("Password policy should require symbols")

            if not policy.get('RequireNumbers', False):
                violations.append("Password policy should require numbers")

            if not policy.get('RequireUppercaseCharacters', False):
                violations.append("Password policy should require uppercase characters")

            if not policy.get('RequireLowercaseCharacters', False):
                violations.append("Password policy should require lowercase characters")

            if policy.get('MaxPasswordAge', 365) > 90:
                violations.append("Password maximum age should be 90 days or less")

            results['violations_found'] += len(violations)
            results['remediation_actions'].extend(violations)

        except iam_client.exceptions.NoSuchEntityException:
            results['violations_found'] += 1
            results['remediation_actions'].append("No password policy configured")
        except Exception as e:
            logger.warning(f"Error enforcing password policies: {str(e)}")

    def _parse_duration(self, duration_str: str) -> int:
        """Parse ISO 8601 duration to seconds"""
        try:
            # Simple parser for PT1H, PT30M format
            duration_str = duration_str.upper()
            if duration_str.startswith('PT'):
                duration_str = duration_str[2:]

                total_seconds = 0
                if 'H' in duration_str:
                    hours = int(duration_str.split('H')[0])
                    total_seconds += hours * 3600
                    duration_str = duration_str.split('H', 1)[1] if 'H' in duration_str else ''

                if 'M' in duration_str:
                    minutes = int(duration_str.split('M')[0])
                    total_seconds += minutes * 60

                return total_seconds

            return 3600  # Default to 1 hour

        except Exception:
            return 3600  # Default to 1 hour

def handler(event, context):
    """Lambda handler function"""
    automation = IAMAutomation()

    # Determine action based on event
    action = event.get('action', 'audit')

    try:
        if action == 'audit':
            result = automation.audit_permission_sets()
        elif action == 'cleanup':
            result = automation.cleanup_unused_resources()
        elif action == 'enforce':
            result = automation.enforce_compliance_policies()
        else:
            result = {
                'error': f'Unknown action: {action}',
                'available_actions': ['audit', 'cleanup', 'enforce']
            }

        return {
            'statusCode': 200,
            'body': json.dumps({
                'action': action,
                'timestamp': datetime.utcnow().isoformat(),
                'environment': automation.environment,
                'result': result
            }, indent=2)
        }

    except Exception as e:
        logger.error(f"Handler error: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e),
                'action': action,
                'timestamp': datetime.utcnow().isoformat()
            })
        }

if __name__ == '__main__':
    # For local testing
    test_event = {'action': 'audit'}
    result = handler(test_event, {})
    print(json.dumps(result, indent=2))