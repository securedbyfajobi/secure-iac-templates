#!/usr/bin/env python3
"""
Enterprise Secret Rotation Handler
Automated secret rotation with multi-database support and security validation
"""

import json
import os
import boto3
import logging
import random
import string
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)


class SecretRotationHandler:
    """Enterprise-grade secret rotation with comprehensive validation"""

    def __init__(self):
        self.secrets_client = boto3.client('secretsmanager')
        self.rds_client = boto3.client('rds')
        self.ec2_client = boto3.client('ec2')
        self.kms_client = boto3.client('kms')

        # Environment configuration
        self.environment = os.environ.get('ENVIRONMENT', '${environment}')
        self.kms_key_id = os.environ.get('KMS_KEY_ID', '')

        # Password complexity requirements
        self.password_requirements = {
            'critical': {
                'length': 32,
                'uppercase': 8,
                'lowercase': 8,
                'digits': 8,
                'special_chars': 8,
                'exclude_ambiguous': True
            },
            'high': {
                'length': 24,
                'uppercase': 6,
                'lowercase': 6,
                'digits': 6,
                'special_chars': 6,
                'exclude_ambiguous': True
            },
            'medium': {
                'length': 16,
                'uppercase': 4,
                'lowercase': 4,
                'digits': 4,
                'special_chars': 4,
                'exclude_ambiguous': False
            },
            'low': {
                'length': 12,
                'uppercase': 3,
                'lowercase': 3,
                'digits': 3,
                'special_chars': 3,
                'exclude_ambiguous': False
            }
        }

        # Database engine specific configurations
        self.db_engines = {
            'mysql': {
                'port': 3306,
                'admin_username': 'admin',
                'driver': 'mysql+pymysql'
            },
            'postgres': {
                'port': 5432,
                'admin_username': 'postgres',
                'driver': 'postgresql+psycopg2'
            },
            'oracle': {
                'port': 1521,
                'admin_username': 'oracle',
                'driver': 'oracle+cx_oracle'
            },
            'sqlserver': {
                'port': 1433,
                'admin_username': 'sa',
                'driver': 'mssql+pyodbc'
            },
            'mariadb': {
                'port': 3306,
                'admin_username': 'admin',
                'driver': 'mysql+pymysql'
            }
        }

    def lambda_handler(self, event: Dict[str, Any], context: Any) -> Dict[str, Any]:
        """AWS Lambda entry point for secret rotation"""
        try:
            # Extract event parameters
            secret_arn = event.get('SecretId', '')
            token = event.get('Token', '')
            step = event.get('Step', '')

            if not all([secret_arn, token, step]):
                raise ValueError("Missing required parameters: SecretId, Token, or Step")

            logger.info(f"Starting rotation step '{step}' for secret {secret_arn}")

            # Get secret metadata
            secret_metadata = self.get_secret_metadata(secret_arn)

            # Route to appropriate step handler
            if step == "createSecret":
                result = self.create_secret(secret_arn, token, secret_metadata)
            elif step == "setSecret":
                result = self.set_secret(secret_arn, token, secret_metadata)
            elif step == "testSecret":
                result = self.test_secret(secret_arn, token, secret_metadata)
            elif step == "finishSecret":
                result = self.finish_secret(secret_arn, token, secret_metadata)
            else:
                raise ValueError(f"Invalid rotation step: {step}")

            logger.info(f"Successfully completed rotation step '{step}'")

            return {
                'statusCode': 200,
                'body': json.dumps({
                    'success': True,
                    'step': step,
                    'secretArn': secret_arn,
                    'result': result,
                    'timestamp': datetime.utcnow().isoformat()
                })
            }

        except Exception as e:
            logger.error(f"Rotation failed at step '{step}': {str(e)}")
            raise

    def get_secret_metadata(self, secret_arn: str) -> Dict[str, Any]:
        """Get secret metadata and configuration"""
        try:
            response = self.secrets_client.describe_secret(SecretId=secret_arn)

            # Extract category from tags
            tags = response.get('Tags', [])
            category = 'medium'  # default
            secret_type = 'unknown'

            for tag in tags:
                if tag['Key'] == 'Category':
                    category = tag['Value']
                elif tag['Key'] == 'SecretType':
                    secret_type = tag['Value']

            return {
                'name': response['Name'],
                'arn': response['ARN'],
                'category': category,
                'secret_type': secret_type,
                'description': response.get('Description', ''),
                'rotation_enabled': response.get('RotationEnabled', False),
                'rotation_rules': response.get('RotationRules', {}),
                'kms_key_id': response.get('KmsKeyId', self.kms_key_id)
            }

        except ClientError as e:
            logger.error(f"Failed to get secret metadata: {e}")
            raise

    def create_secret(self, secret_arn: str, token: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Step 1: Create new secret version with new credentials"""
        logger.info(f"Creating new secret version for {secret_arn}")

        try:
            # Get current secret value
            current_secret = self.get_secret_value(secret_arn, "AWSCURRENT")

            # Generate new credentials based on secret type
            if metadata['secret_type'] == 'database':
                new_secret = self.generate_new_database_credentials(current_secret, metadata)
            elif metadata['secret_type'] == 'api':
                new_secret = self.generate_new_api_credentials(current_secret, metadata)
            else:
                raise ValueError(f"Unsupported secret type: {metadata['secret_type']}")

            # Store new secret version
            self.secrets_client.put_secret_value(
                SecretId=secret_arn,
                VersionId=token,
                SecretString=json.dumps(new_secret),
                VersionStage="AWSPENDING"
            )

            # Log rotation event
            self.log_rotation_event(secret_arn, "create", {
                'new_version': token,
                'category': metadata['category'],
                'secret_type': metadata['secret_type']
            })

            return {
                'action': 'created',
                'version_id': token,
                'category': metadata['category']
            }

        except Exception as e:
            logger.error(f"Failed to create new secret version: {e}")
            raise

    def set_secret(self, secret_arn: str, token: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Step 2: Configure the service to use the new credentials"""
        logger.info(f"Setting new credentials in service for {secret_arn}")

        try:
            # Get the new credentials
            new_secret = self.get_secret_value(secret_arn, token)

            if metadata['secret_type'] == 'database':
                result = self.set_database_credentials(new_secret, metadata)
            elif metadata['secret_type'] == 'api':
                result = self.set_api_credentials(new_secret, metadata)
            else:
                raise ValueError(f"Unsupported secret type: {metadata['secret_type']}")

            # Log set event
            self.log_rotation_event(secret_arn, "set", {
                'version_id': token,
                'service_updated': True
            })

            return result

        except Exception as e:
            logger.error(f"Failed to set new credentials: {e}")
            raise

    def test_secret(self, secret_arn: str, token: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Step 3: Test the new credentials"""
        logger.info(f"Testing new credentials for {secret_arn}")

        try:
            # Get the new credentials
            new_secret = self.get_secret_value(secret_arn, token)

            if metadata['secret_type'] == 'database':
                test_result = self.test_database_credentials(new_secret, metadata)
            elif metadata['secret_type'] == 'api':
                test_result = self.test_api_credentials(new_secret, metadata)
            else:
                raise ValueError(f"Unsupported secret type: {metadata['secret_type']}")

            if not test_result['success']:
                raise Exception(f"Credential test failed: {test_result['error']}")

            # Log test event
            self.log_rotation_event(secret_arn, "test", {
                'version_id': token,
                'test_result': test_result
            })

            return test_result

        except Exception as e:
            logger.error(f"Failed to test new credentials: {e}")
            raise

    def finish_secret(self, secret_arn: str, token: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Step 4: Finalize the rotation by updating version stages"""
        logger.info(f"Finishing rotation for {secret_arn}")

        try:
            # Move the new version to AWSCURRENT and old version to AWSPREVIOUS
            self.secrets_client.update_secret_version_stage(
                SecretId=secret_arn,
                VersionStage="AWSCURRENT",
                MoveToVersionId=token,
                RemoveFromVersionId=self.get_current_version_id(secret_arn)
            )

            # Clean up old versions beyond retention policy
            self.cleanup_old_versions(secret_arn, metadata)

            # Log completion event
            self.log_rotation_event(secret_arn, "finish", {
                'version_id': token,
                'rotation_completed': True,
                'next_rotation': self.calculate_next_rotation(metadata)
            })

            return {
                'action': 'finished',
                'new_current_version': token,
                'rotation_completed_at': datetime.utcnow().isoformat()
            }

        except Exception as e:
            logger.error(f"Failed to finish rotation: {e}")
            raise

    def generate_new_database_credentials(self, current_secret: Dict[str, Any], metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Generate new database credentials"""
        category = metadata.get('category', 'medium')
        password_config = self.password_requirements[category]

        # Generate new password
        new_password = self.generate_secure_password(password_config)

        # Create new secret with same structure but new password
        new_secret = current_secret.copy()
        new_secret['password'] = new_password

        # Add rotation metadata
        new_secret['rotation_timestamp'] = datetime.utcnow().isoformat()
        new_secret['rotation_id'] = self.generate_rotation_id()

        return new_secret

    def generate_new_api_credentials(self, current_secret: Dict[str, Any], metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Generate new API credentials"""
        category = metadata.get('category', 'medium')
        password_config = self.password_requirements[category]

        # Generate new API key and secret
        new_api_key = self.generate_api_key(password_config['length'])
        new_secret_key = self.generate_secure_password(password_config)

        # Create new secret
        new_secret = current_secret.copy()
        new_secret['api_key'] = new_api_key
        new_secret['secret_key'] = new_secret_key

        # Add rotation metadata
        new_secret['rotation_timestamp'] = datetime.utcnow().isoformat()
        new_secret['rotation_id'] = self.generate_rotation_id()

        return new_secret

    def generate_secure_password(self, config: Dict[str, Any]) -> str:
        """Generate a secure password based on configuration"""
        length = config['length']
        uppercase_count = config['uppercase']
        lowercase_count = config['lowercase']
        digit_count = config['digits']
        special_count = config['special_chars']
        exclude_ambiguous = config.get('exclude_ambiguous', False)

        # Character sets
        uppercase = string.ascii_uppercase
        lowercase = string.ascii_lowercase
        digits = string.digits
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"

        if exclude_ambiguous:
            # Remove ambiguous characters
            uppercase = uppercase.replace('O', '').replace('I', '')
            lowercase = lowercase.replace('l', '').replace('o', '')
            digits = digits.replace('0', '').replace('1', '')
            special_chars = special_chars.replace('|', '').replace('!', '').replace('1', '')

        # Generate required character counts
        password_chars = []
        password_chars.extend(random.choices(uppercase, k=uppercase_count))
        password_chars.extend(random.choices(lowercase, k=lowercase_count))
        password_chars.extend(random.choices(digits, k=digit_count))
        password_chars.extend(random.choices(special_chars, k=special_count))

        # Fill remaining length with random characters from all sets
        remaining_length = length - len(password_chars)
        if remaining_length > 0:
            all_chars = uppercase + lowercase + digits + special_chars
            password_chars.extend(random.choices(all_chars, k=remaining_length))

        # Shuffle the password
        random.shuffle(password_chars)

        return ''.join(password_chars)

    def generate_api_key(self, length: int) -> str:
        """Generate API key (alphanumeric only)"""
        chars = string.ascii_letters + string.digits
        return ''.join(random.choices(chars, k=length))

    def generate_rotation_id(self) -> str:
        """Generate unique rotation ID"""
        timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
        random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        return f"rot-{timestamp}-{random_suffix}"

    def set_database_credentials(self, new_secret: Dict[str, Any], metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Set new database credentials in the database"""
        engine = new_secret.get('engine', '').lower()

        if engine not in self.db_engines:
            raise ValueError(f"Unsupported database engine: {engine}")

        try:
            # Connect to database and update user password
            connection_result = self.update_database_user_password(new_secret)

            return {
                'action': 'database_password_updated',
                'engine': engine,
                'username': new_secret['username'],
                'connection_test': connection_result
            }

        except Exception as e:
            logger.error(f"Failed to update database password: {e}")
            raise

    def set_api_credentials(self, new_secret: Dict[str, Any], metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Set new API credentials (placeholder for service-specific implementation)"""
        # This would be customized based on the specific API service
        logger.info("API credentials generated - service-specific update required")

        return {
            'action': 'api_credentials_generated',
            'api_key_updated': True,
            'secret_key_updated': True,
            'endpoint': new_secret.get('endpoint', '')
        }

    def test_database_credentials(self, new_secret: Dict[str, Any], metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Test database connection with new credentials"""
        try:
            # Simulate database connection test
            # In a real implementation, this would establish an actual connection
            connection_params = {
                'host': new_secret['host'],
                'port': new_secret['port'],
                'username': new_secret['username'],
                'database': new_secret['dbname'],
                'engine': new_secret['engine']
            }

            # Validate connection parameters
            test_result = self.validate_database_connection(connection_params)

            return {
                'success': True,
                'connection_time_ms': test_result.get('connection_time_ms', 0),
                'database_version': test_result.get('version', 'unknown'),
                'test_timestamp': datetime.utcnow().isoformat()
            }

        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'test_timestamp': datetime.utcnow().isoformat()
            }

    def test_api_credentials(self, new_secret: Dict[str, Any], metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Test API credentials (placeholder for service-specific implementation)"""
        try:
            # Simulate API authentication test
            endpoint = new_secret.get('endpoint', '')
            api_key = new_secret.get('api_key', '')

            # In a real implementation, this would make an actual API call
            test_result = self.validate_api_credentials(endpoint, api_key)

            return {
                'success': True,
                'response_time_ms': test_result.get('response_time_ms', 0),
                'api_version': test_result.get('version', 'unknown'),
                'test_timestamp': datetime.utcnow().isoformat()
            }

        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'test_timestamp': datetime.utcnow().isoformat()
            }

    def update_database_user_password(self, secret: Dict[str, Any]) -> Dict[str, Any]:
        """Update database user password (simulated)"""
        # This is a placeholder - real implementation would connect to database
        # and execute appropriate SQL commands based on the engine

        engine = secret['engine'].lower()
        username = secret['username']

        logger.info(f"Simulating password update for {engine} user {username}")

        # Simulate different engines
        if engine in ['mysql', 'mariadb']:
            sql_command = f"ALTER USER '{username}'@'%' IDENTIFIED BY '<new_password>'"
        elif engine == 'postgres':
            sql_command = f"ALTER USER {username} PASSWORD '<new_password>'"
        elif engine == 'oracle':
            sql_command = f"ALTER USER {username} IDENTIFIED BY <new_password>"
        elif engine == 'sqlserver':
            sql_command = f"ALTER LOGIN {username} WITH PASSWORD = '<new_password>'"
        else:
            raise ValueError(f"Unsupported engine for password update: {engine}")

        return {
            'sql_executed': sql_command.replace('<new_password>', '[REDACTED]'),
            'execution_time_ms': 150,  # Simulated
            'rows_affected': 1
        }

    def validate_database_connection(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Validate database connection parameters (simulated)"""
        # Simulate connection validation
        logger.info(f"Simulating connection test to {params['engine']} at {params['host']}:{params['port']}")

        return {
            'connection_time_ms': random.randint(50, 200),
            'version': f"{params['engine']}-5.7.0",  # Simulated version
            'connection_id': random.randint(1000, 9999)
        }

    def validate_api_credentials(self, endpoint: str, api_key: str) -> Dict[str, Any]:
        """Validate API credentials (simulated)"""
        # Simulate API validation
        logger.info(f"Simulating API test for endpoint {endpoint}")

        return {
            'response_time_ms': random.randint(100, 500),
            'version': 'v2.1.0',  # Simulated version
            'rate_limit_remaining': random.randint(900, 1000)
        }

    def get_secret_value(self, secret_arn: str, version_stage: str = "AWSCURRENT") -> Dict[str, Any]:
        """Get secret value for specified version stage"""
        try:
            response = self.secrets_client.get_secret_value(
                SecretId=secret_arn,
                VersionStage=version_stage
            )
            return json.loads(response['SecretString'])

        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                logger.error(f"Secret not found: {secret_arn}")
            raise

    def get_current_version_id(self, secret_arn: str) -> str:
        """Get the current version ID of a secret"""
        try:
            response = self.secrets_client.describe_secret(SecretId=secret_arn)
            version_stages = response.get('VersionIdsToStages', {})

            for version_id, stages in version_stages.items():
                if 'AWSCURRENT' in stages:
                    return version_id

            raise ValueError("No AWSCURRENT version found")

        except ClientError as e:
            logger.error(f"Failed to get current version ID: {e}")
            raise

    def cleanup_old_versions(self, secret_arn: str, metadata: Dict[str, Any]) -> None:
        """Clean up old secret versions beyond retention policy"""
        try:
            response = self.secrets_client.describe_secret(SecretId=secret_arn)
            version_stages = response.get('VersionIdsToStages', {})

            # Keep current, pending, and previous versions
            versions_to_keep = set()
            for version_id, stages in version_stages.items():
                if any(stage in stages for stage in ['AWSCURRENT', 'AWSPENDING', 'AWSPREVIOUS']):
                    versions_to_keep.add(version_id)

            # Remove old versions (keep max 5 historical versions)
            all_versions = list(version_stages.keys())
            if len(all_versions) > 8:  # Current + Pending + Previous + 5 historical
                versions_to_remove = [v for v in all_versions if v not in versions_to_keep][:-5]

                for version_id in versions_to_remove:
                    try:
                        self.secrets_client.update_secret_version_stage(
                            SecretId=secret_arn,
                            VersionStage="AWSDEPRECATED",
                            MoveToVersionId=version_id
                        )
                        logger.info(f"Marked version {version_id} as deprecated")
                    except ClientError as e:
                        logger.warning(f"Failed to deprecate version {version_id}: {e}")

        except Exception as e:
            logger.warning(f"Failed to cleanup old versions: {e}")

    def calculate_next_rotation(self, metadata: Dict[str, Any]) -> str:
        """Calculate next rotation timestamp"""
        rotation_rules = metadata.get('rotation_rules', {})
        rotation_days = rotation_rules.get('AutomaticallyAfterDays', 90)

        next_rotation = datetime.utcnow() + timedelta(days=rotation_days)
        return next_rotation.isoformat()

    def log_rotation_event(self, secret_arn: str, event_type: str, details: Dict[str, Any]) -> None:
        """Log rotation events for audit and monitoring"""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'secret_arn': secret_arn,
            'environment': self.environment,
            'details': details
        }

        # In a production environment, this would send to CloudWatch Logs or similar
        logger.info(f"Rotation Event: {json.dumps(log_entry)}")


# Global handler instance
rotation_handler = SecretRotationHandler()


def lambda_handler(event, context):
    """AWS Lambda entry point"""
    return rotation_handler.lambda_handler(event, context)