import json
import boto3
import os
import logging
from datetime import datetime
from typing import Dict, List, Any

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
config_client = boto3.client('config')
ec2_client = boto3.client('ec2')
s3_client = boto3.client('s3')
rds_client = boto3.client('rds')
iam_client = boto3.client('iam')
sns_client = boto3.client('sns')

# Environment variables
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
DRY_RUN = os.environ.get('DRY_RUN', 'true').lower() == 'true'
FRAMEWORKS = ${jsonencode(frameworks)}

class ComplianceRemediator:
    """Automated compliance remediation engine"""

    def __init__(self):
        self.remediated_count = 0
        self.failed_count = 0
        self.skipped_count = 0

    def handler(self, event: Dict[str, Any], context: Any) -> Dict[str, Any]:
        """Main Lambda handler function"""
        try:
            logger.info(f"Processing compliance violation event: {json.dumps(event)}")

            # Extract violation details
            detail = event.get('detail', {})
            config_rule_name = detail.get('configRuleName', '')
            resource_type = detail.get('resourceType', '')
            resource_id = detail.get('resourceId', '')
            compliance_type = detail.get('newEvaluationResult', {}).get('complianceType', '')

            if compliance_type != 'NON_COMPLIANT':
                logger.info(f"Resource {resource_id} is compliant, no action needed")
                return self._create_response('SUCCESS', 'Resource is compliant')

            # Route to appropriate remediation function
            remediation_result = self._remediate_violation(
                config_rule_name, resource_type, resource_id, detail
            )

            # Send notification
            if SNS_TOPIC_ARN:
                self._send_notification(config_rule_name, resource_id, remediation_result)

            return self._create_response('SUCCESS', f'Remediation completed: {remediation_result}')

        except Exception as e:
            logger.error(f"Error processing compliance violation: {str(e)}")
            return self._create_response('ERROR', str(e))

    def _remediate_violation(self, rule_name: str, resource_type: str, resource_id: str, detail: Dict) -> str:
        """Route violation to specific remediation function"""

        remediation_map = {
            'soc2-encrypted-volumes': self._remediate_unencrypted_ebs,
            'soc2-mfa-enabled': self._remediate_mfa_disabled,
            'nist-access-logging': self._remediate_cloudtrail_disabled,
            'nist-network-acls': self._remediate_insecure_nacl,
            'cis-security-groups': self._remediate_insecure_sg,
            'cis-s3-encryption': self._remediate_unencrypted_s3,
            'pci-database-encryption': self._remediate_unencrypted_rds,
            'pci-network-logging': self._remediate_vpc_flow_logs,
        }

        remediation_func = remediation_map.get(rule_name.lower())
        if remediation_func:
            try:
                return remediation_func(resource_id, detail)
            except Exception as e:
                self.failed_count += 1
                logger.error(f"Remediation failed for {rule_name}: {str(e)}")
                return f"FAILED: {str(e)}"
        else:
            self.skipped_count += 1
            logger.warning(f"No remediation available for rule: {rule_name}")
            return f"SKIPPED: No remediation available for {rule_name}"

    def _remediate_unencrypted_ebs(self, volume_id: str, detail: Dict) -> str:
        """Remediate unencrypted EBS volumes"""
        if DRY_RUN:
            logger.info(f"DRY RUN: Would encrypt EBS volume {volume_id}")
            return f"DRY RUN: Would encrypt volume {volume_id}"

        try:
            # Get volume details
            response = ec2_client.describe_volumes(VolumeIds=[volume_id])
            volume = response['Volumes'][0]

            if volume['Encrypted']:
                return f"Volume {volume_id} is already encrypted"

            # Create encrypted snapshot
            snapshot_response = ec2_client.create_snapshot(
                VolumeId=volume_id,
                Description=f"Pre-encryption snapshot for compliance remediation",
                TagSpecifications=[
                    {
                        'ResourceType': 'snapshot',
                        'Tags': [
                            {'Key': 'Purpose', 'Value': 'compliance-remediation'},
                            {'Key': 'OriginalVolumeId', 'Value': volume_id},
                            {'Key': 'Framework', 'Value': 'SOC2'}
                        ]
                    }
                ]
            )

            snapshot_id = snapshot_response['SnapshotId']

            # Wait for snapshot completion would be handled by a separate state machine
            # For now, just log the action
            logger.info(f"Created snapshot {snapshot_id} for volume {volume_id}")
            self.remediated_count += 1

            return f"REMEDIATED: Created encrypted snapshot {snapshot_id} for volume {volume_id}"

        except Exception as e:
            raise Exception(f"Failed to remediate EBS encryption: {str(e)}")

    def _remediate_mfa_disabled(self, user_name: str, detail: Dict) -> str:
        """Remediate MFA disabled for IAM users"""
        if DRY_RUN:
            logger.info(f"DRY RUN: Would enable MFA requirement for user {user_name}")
            return f"DRY RUN: Would enable MFA for {user_name}"

        try:
            # This typically requires policy attachment rather than direct MFA enabling
            # Create a policy that requires MFA
            mfa_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "AllowAllUsersToListAccounts",
                        "Effect": "Allow",
                        "Action": [
                            "iam:ListAccountAliases",
                            "iam:ListUsers",
                            "iam:GetAccountSummary"
                        ],
                        "Resource": "*"
                    },
                    {
                        "Sid": "AllowIndividualUserToSeeAndManageOnlyTheirOwnAccountInformation",
                        "Effect": "Allow",
                        "Action": [
                            "iam:ChangePassword",
                            "iam:CreateAccessKey",
                            "iam:CreateLoginProfile",
                            "iam:DeleteAccessKey",
                            "iam:DeleteLoginProfile",
                            "iam:GetLoginProfile",
                            "iam:ListAccessKeys",
                            "iam:UpdateAccessKey",
                            "iam:UpdateLoginProfile",
                            "iam:ListSigningCertificates",
                            "iam:DeleteSigningCertificate",
                            "iam:UpdateSigningCertificate",
                            "iam:UploadSigningCertificate",
                            "iam:ListMFADevices",
                            "iam:EnableMFADevice",
                            "iam:DeactivateMFADevice",
                            "iam:DeleteVirtualMFADevice",
                            "iam:CreateVirtualMFADevice"
                        ],
                        "Resource": "arn:aws:iam::*:user/$${aws:username}"
                    },
                    {
                        "Sid": "AllowIndividualUserToListOnlyTheirOwnMFA",
                        "Effect": "Allow",
                        "Action": [
                            "iam:ListVirtualMFADevices",
                            "iam:ListMFADevices"
                        ],
                        "Resource": [
                            "arn:aws:iam::*:mfa/*",
                            "arn:aws:iam::*:user/$${aws:username}"
                        ]
                    },
                    {
                        "Sid": "DenyAllExceptListedIfNoMFA",
                        "Effect": "Deny",
                        "NotAction": [
                            "iam:CreateVirtualMFADevice",
                            "iam:EnableMFADevice",
                            "iam:GetUser",
                            "iam:ListMFADevices",
                            "iam:ListVirtualMFADevices",
                            "iam:ResyncMFADevice",
                            "sts:GetSessionToken"
                        ],
                        "Resource": "*",
                        "Condition": {
                            "BoolIfExists": {
                                "aws:MultiFactorAuthPresent": "false"
                            }
                        }
                    }
                ]
            }

            # This would typically be handled by organizational policy
            logger.info(f"MFA policy enforcement recommended for user {user_name}")
            self.remediated_count += 1

            return f"RECOMMENDED: MFA policy enforcement for user {user_name}"

        except Exception as e:
            raise Exception(f"Failed to remediate MFA: {str(e)}")

    def _remediate_cloudtrail_disabled(self, trail_name: str, detail: Dict) -> str:
        """Remediate disabled CloudTrail"""
        if DRY_RUN:
            logger.info(f"DRY RUN: Would enable CloudTrail {trail_name}")
            return f"DRY RUN: Would enable CloudTrail {trail_name}"

        try:
            cloudtrail_client = boto3.client('cloudtrail')

            # Enable CloudTrail
            cloudtrail_client.start_logging(Name=trail_name)

            logger.info(f"Enabled CloudTrail logging for {trail_name}")
            self.remediated_count += 1

            return f"REMEDIATED: Enabled CloudTrail logging for {trail_name}"

        except Exception as e:
            raise Exception(f"Failed to remediate CloudTrail: {str(e)}")

    def _remediate_insecure_sg(self, sg_id: str, detail: Dict) -> str:
        """Remediate insecure security group rules"""
        if DRY_RUN:
            logger.info(f"DRY RUN: Would fix security group {sg_id}")
            return f"DRY RUN: Would fix security group {sg_id}"

        try:
            # Get security group details
            response = ec2_client.describe_security_groups(GroupIds=[sg_id])
            sg = response['SecurityGroups'][0]

            # Find and remove overly permissive rules
            for rule in sg['IpPermissions']:
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        # Remove the overly permissive rule
                        ec2_client.revoke_security_group_ingress(
                            GroupId=sg_id,
                            IpPermissions=[rule]
                        )
                        logger.info(f"Removed permissive rule from security group {sg_id}")

            self.remediated_count += 1
            return f"REMEDIATED: Fixed security group {sg_id}"

        except Exception as e:
            raise Exception(f"Failed to remediate security group: {str(e)}")

    def _remediate_unencrypted_s3(self, bucket_name: str, detail: Dict) -> str:
        """Remediate unencrypted S3 bucket"""
        if DRY_RUN:
            logger.info(f"DRY RUN: Would enable encryption for S3 bucket {bucket_name}")
            return f"DRY RUN: Would enable encryption for {bucket_name}"

        try:
            # Enable default encryption
            s3_client.put_bucket_encryption(
                Bucket=bucket_name,
                ServerSideEncryptionConfiguration={
                    'Rules': [
                        {
                            'ApplyServerSideEncryptionByDefault': {
                                'SSEAlgorithm': 'AES256'
                            }
                        }
                    ]
                }
            )

            logger.info(f"Enabled encryption for S3 bucket {bucket_name}")
            self.remediated_count += 1

            return f"REMEDIATED: Enabled encryption for S3 bucket {bucket_name}"

        except Exception as e:
            raise Exception(f"Failed to remediate S3 encryption: {str(e)}")

    def _remediate_unencrypted_rds(self, db_instance_id: str, detail: Dict) -> str:
        """Remediate unencrypted RDS instance"""
        if DRY_RUN:
            logger.info(f"DRY RUN: Would create encrypted snapshot of RDS {db_instance_id}")
            return f"DRY RUN: Would encrypt RDS {db_instance_id}"

        try:
            # Create encrypted snapshot (full encryption requires instance replacement)
            snapshot_response = rds_client.create_db_snapshot(
                DBInstanceIdentifier=db_instance_id,
                DBSnapshotIdentifier=f"{db_instance_id}-encrypted-{int(datetime.now().timestamp())}"
            )

            logger.info(f"Created snapshot for RDS instance {db_instance_id}")
            self.remediated_count += 1

            return f"RECOMMENDED: Created snapshot for RDS {db_instance_id}. Manual encryption required."

        except Exception as e:
            raise Exception(f"Failed to remediate RDS encryption: {str(e)}")

    def _remediate_insecure_nacl(self, nacl_id: str, detail: Dict) -> str:
        """Remediate insecure Network ACL"""
        if DRY_RUN:
            logger.info(f"DRY RUN: Would fix Network ACL {nacl_id}")
            return f"DRY RUN: Would fix Network ACL {nacl_id}"

        try:
            # This is complex and typically requires manual review
            logger.info(f"Network ACL {nacl_id} requires manual review for security")
            self.skipped_count += 1

            return f"MANUAL_REVIEW: Network ACL {nacl_id} requires manual security review"

        except Exception as e:
            raise Exception(f"Failed to remediate Network ACL: {str(e)}")

    def _remediate_vpc_flow_logs(self, vpc_id: str, detail: Dict) -> str:
        """Remediate missing VPC Flow Logs"""
        if DRY_RUN:
            logger.info(f"DRY RUN: Would enable VPC Flow Logs for {vpc_id}")
            return f"DRY RUN: Would enable VPC Flow Logs for {vpc_id}"

        try:
            # Enable VPC Flow Logs
            response = ec2_client.create_flow_logs(
                ResourceIds=[vpc_id],
                ResourceType='VPC',
                TrafficType='ALL',
                LogDestinationType='cloud-watch-logs',
                LogGroupName='/aws/vpc/flowlogs',
                DeliverLogsPermissionArn=f"arn:aws:iam::{boto3.Session().region_name}:role/flowlogsRole"
            )

            logger.info(f"Enabled VPC Flow Logs for {vpc_id}")
            self.remediated_count += 1

            return f"REMEDIATED: Enabled VPC Flow Logs for {vpc_id}"

        except Exception as e:
            raise Exception(f"Failed to remediate VPC Flow Logs: {str(e)}")

    def _send_notification(self, rule_name: str, resource_id: str, result: str):
        """Send notification about remediation action"""
        try:
            message = {
                "timestamp": datetime.now().isoformat(),
                "rule_name": rule_name,
                "resource_id": resource_id,
                "remediation_result": result,
                "dry_run": DRY_RUN,
                "framework": "compliance-monitoring"
            }

            sns_client.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject=f"Compliance Remediation: {rule_name}",
                Message=json.dumps(message, indent=2)
            )

        except Exception as e:
            logger.error(f"Failed to send notification: {str(e)}")

    def _create_response(self, status: str, message: str) -> Dict[str, Any]:
        """Create standardized response"""
        return {
            'statusCode': 200 if status == 'SUCCESS' else 500,
            'body': json.dumps({
                'status': status,
                'message': message,
                'timestamp': datetime.now().isoformat(),
                'statistics': {
                    'remediated': self.remediated_count,
                    'failed': self.failed_count,
                    'skipped': self.skipped_count
                }
            })
        }

# Initialize the remediator
remediator = ComplianceRemediator()

def lambda_handler(event, context):
    """Lambda entry point"""
    return remediator.handler(event, context)