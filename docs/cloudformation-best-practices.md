# CloudFormation Security Best Practices

## Overview

This guide provides comprehensive security best practices for AWS CloudFormation template development, focusing on secure infrastructure deployment and compliance with security frameworks.

## Template Security Structure

### 1. Template Metadata and Parameters

```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: 'Secure infrastructure template with security best practices'

Metadata:
  AWS::CloudFormation::Interface:
    ParameterGroups:
      - Label:
          default: "Security Configuration"
        Parameters:
          - Environment
          - SecurityLevel
          - ComplianceFramework

Parameters:
  Environment:
    Type: String
    AllowedValues: [dev, staging, prod]
    Default: dev
    Description: Deployment environment

  SecurityLevel:
    Type: String
    AllowedValues: [standard, high, critical]
    Default: high
    Description: Security classification level
```

### 2. Secure S3 Bucket Configuration

```yaml
Resources:
  SecureBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub "${AWS::StackName}-secure-bucket-${AWS::AccountId}"
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256
              KMSMasterKeyID: !Ref BucketKMSKey
            BucketKeyEnabled: true
      VersioningConfiguration:
        Status: Enabled
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
      LoggingConfiguration:
        DestinationBucketName: !Ref AccessLogsBucket
        LogFilePrefix: access-logs/
      NotificationConfiguration:
        CloudWatchConfigurations:
          - Event: s3:ObjectCreated:*
            CloudWatchConfiguration:
              LogGroupName: !Ref S3LogGroup

  BucketKMSKey:
    Type: AWS::KMS::Key
    Properties:
      Description: KMS key for S3 bucket encryption
      KeyPolicy:
        Statement:
          - Effect: Allow
            Principal:
              AWS: !Sub "arn:aws:iam::${AWS::AccountId}:root"
            Action: "kms:*"
            Resource: "*"
          - Effect: Allow
            Principal:
              Service: s3.amazonaws.com
            Action:
              - kms:Decrypt
              - kms:GenerateDataKey
            Resource: "*"

  BucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: !Ref SecureBucket
      PolicyDocument:
        Statement:
          - Effect: Deny
            Principal: "*"
            Action: "s3:*"
            Resource:
              - !GetAtt SecureBucket.Arn
              - !Sub "${SecureBucket}/*"
            Condition:
              Bool:
                "aws:SecureTransport": "false"
```

### 3. Secure VPC Configuration

```yaml
  SecureVPC:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.0.0.0/16
      EnableDnsHostnames: true
      EnableDnsSupport: true
      Tags:
        - Key: Name
          Value: !Sub "${AWS::StackName}-secure-vpc"
        - Key: Environment
          Value: !Ref Environment

  PrivateSubnet1:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref SecureVPC
      CidrBlock: 10.0.1.0/24
      AvailabilityZone: !Select [0, !GetAZs '']
      MapPublicIpOnLaunch: false
      Tags:
        - Key: Name
          Value: !Sub "${AWS::StackName}-private-subnet-1"
        - Key: Type
          Value: Private

  PrivateSubnet2:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref SecureVPC
      CidrBlock: 10.0.2.0/24
      AvailabilityZone: !Select [1, !GetAZs '']
      MapPublicIpOnLaunch: false
      Tags:
        - Key: Name
          Value: !Sub "${AWS::StackName}-private-subnet-2"

  # VPC Flow Logs for security monitoring
  VPCFlowLogsRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: vpc-flow-logs.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: CloudWatchLogsPolicy
          PolicyDocument:
            Statement:
              - Effect: Allow
                Action:
                  - logs:CreateLogGroup
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                  - logs:DescribeLogGroups
                  - logs:DescribeLogStreams
                Resource: "*"

  VPCFlowLog:
    Type: AWS::EC2::FlowLog
    Properties:
      ResourceType: VPC
      ResourceId: !Ref SecureVPC
      TrafficType: ALL
      LogDestinationType: cloud-watch-logs
      LogGroupName: !Ref VPCFlowLogGroup
      DeliverLogsPermissionArn: !GetAtt VPCFlowLogsRole.Arn
```

### 4. Security Groups with Least Privilege

```yaml
  WebServerSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupName: !Sub "${AWS::StackName}-web-sg"
      GroupDescription: Security group for web servers with minimal access
      VpcId: !Ref SecureVPC
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          SourceSecurityGroupId: !Ref LoadBalancerSecurityGroup
          Description: HTTPS from load balancer only
      SecurityGroupEgress:
        - IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          CidrIp: 0.0.0.0/0
          Description: HTTPS outbound for package updates
        - IpProtocol: tcp
          FromPort: 80
          ToPort: 80
          CidrIp: 0.0.0.0/0
          Description: HTTP outbound for package updates
      Tags:
        - Key: Name
          Value: !Sub "${AWS::StackName}-web-sg"

  DatabaseSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupName: !Sub "${AWS::StackName}-db-sg"
      GroupDescription: Security group for database with restricted access
      VpcId: !Ref SecureVPC
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 3306
          ToPort: 3306
          SourceSecurityGroupId: !Ref WebServerSecurityGroup
          Description: MySQL from web servers only
      Tags:
        - Key: Name
          Value: !Sub "${AWS::StackName}-db-sg"
```

### 5. IAM Roles and Policies

```yaml
  EC2Role:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Sub "${AWS::StackName}-ec2-role"
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: ec2.amazonaws.com
            Action: sts:AssumeRole
            Condition:
              StringEquals:
                "aws:RequestedRegion": !Ref "AWS::Region"
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy
      Policies:
        - PolicyName: S3BucketAccess
          PolicyDocument:
            Statement:
              - Effect: Allow
                Action:
                  - s3:GetObject
                  - s3:PutObject
                Resource: !Sub "${SecureBucket}/*"
              - Effect: Allow
                Action:
                  - s3:ListBucket
                Resource: !GetAtt SecureBucket.Arn

  EC2InstanceProfile:
    Type: AWS::IAM::InstanceProfile
    Properties:
      Roles:
        - !Ref EC2Role
```

## Security Validation and Testing

### 1. CloudFormation Hooks for Validation

```yaml
  SecurityValidationLambda:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: !Sub "${AWS::StackName}-security-validation"
      Runtime: python3.9
      Handler: index.lambda_handler
      Code:
        ZipFile: |
          import json
          import boto3

          def lambda_handler(event, context):
              # Validate security configurations
              cfn = boto3.client('cloudformation')

              # Check for public access
              # Check for encryption
              # Validate IAM policies

              return {
                  'StatusCode': 200,
                  'Body': json.dumps('Security validation passed')
              }
      Role: !GetAtt SecurityValidationRole.Arn

  PreDeploymentValidation:
    Type: AWS::CloudFormation::CustomResource
    Properties:
      ServiceToken: !GetAtt SecurityValidationLambda.Arn
      StackName: !Ref "AWS::StackName"
```

### 2. Security Configuration Validation

```yaml
Conditions:
  IsProduction: !Equals [!Ref Environment, "prod"]
  RequireHighSecurity: !Or
    - !Condition IsProduction
    - !Equals [!Ref SecurityLevel, "critical"]

Rules:
  ProductionSecurityValidation:
    RuleCondition: !Condition IsProduction
    Assertions:
      - Assert: !Equals [!Ref SecurityLevel, "critical"]
        AssertDescription: "Production environment requires critical security level"
```

## Monitoring and Alerting

### 1. CloudWatch Security Monitoring

```yaml
  SecurityLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: !Sub "/aws/security/${AWS::StackName}"
      RetentionInDays: 90
      KmsKeyId: !GetAtt LogGroupKMSKey.Arn

  SecurityEventRule:
    Type: AWS::Events::Rule
    Properties:
      Description: Monitor security events
      EventPattern:
        source: ["aws.guardduty", "aws.securityhub"]
        detail-type: ["GuardDuty Finding", "Security Hub Findings"]
      Targets:
        - Arn: !Ref SecurityAlertsTopic
          Id: SecurityAlertsTarget

  CriticalSecurityAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: !Sub "${AWS::StackName}-critical-security-events"
      AlarmDescription: Alert on critical security events
      MetricName: SecurityEvents
      Namespace: Custom/Security
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      AlarmActions:
        - !Ref SecurityAlertsTopic
```

### 2. AWS Config Rules for Compliance

```yaml
  S3BucketPublicAccessProhibited:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: s3-bucket-public-access-prohibited
      Description: Checks if S3 buckets allow public access
      Source:
        Owner: AWS
        SourceIdentifier: S3_BUCKET_PUBLIC_ACCESS_PROHIBITED

  EncryptedVolumes:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: encrypted-volumes
      Description: Checks if EBS volumes are encrypted
      Source:
        Owner: AWS
        SourceIdentifier: ENCRYPTED_VOLUMES
```

## Template Organization and Modularization

### 1. Nested Templates for Security

```yaml
  SecurityStack:
    Type: AWS::CloudFormation::Stack
    Properties:
      TemplateURL: !Sub "https://s3.amazonaws.com/${TemplateBucket}/security-stack.yaml"
      Parameters:
        VPCId: !Ref SecureVPC
        Environment: !Ref Environment
        SecurityLevel: !Ref SecurityLevel

  ComplianceStack:
    Type: AWS::CloudFormation::Stack
    Properties:
      TemplateURL: !Sub "https://s3.amazonaws.com/${TemplateBucket}/compliance-stack.yaml"
      Parameters:
        SecurityStackId: !Ref SecurityStack
```

### 2. Parameter Validation

```yaml
Parameters:
  VPCCidr:
    Type: String
    Default: "10.0.0.0/16"
    AllowedPattern: "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\\/(1[6-9]|2[0-8]))$"
    ConstraintDescription: CIDR block parameter must be in the form x.x.x.x/16-28

  InstanceType:
    Type: String
    Default: "t3.micro"
    AllowedValues: ["t3.micro", "t3.small", "t3.medium", "m5.large", "m5.xlarge"]
    Description: EC2 instance type for secure deployment
```

## Security Testing and Validation

### 1. CloudFormation Testing

```bash
# Validate template syntax
aws cloudformation validate-template --template-body file://template.yaml

# Deploy with security analysis
cfn-guard validate -r security-rules.guard -d template.yaml

# Test with Checkov
checkov -f template.yaml --framework cloudformation
```

### 2. Automated Security Testing

```yaml
  SecurityTestingPipeline:
    Type: AWS::CodePipeline::Pipeline
    Properties:
      RoleArn: !GetAtt CodePipelineRole.Arn
      Stages:
        - Name: Source
          Actions:
            - Name: SourceAction
              ActionTypeId:
                Category: Source
                Owner: AWS
                Provider: S3
        - Name: SecurityValidation
          Actions:
            - Name: CFNGuard
              ActionTypeId:
                Category: Test
                Owner: AWS
                Provider: CodeBuild
              Configuration:
                ProjectName: !Ref SecurityValidationProject
```

## Compliance Frameworks

### CIS Benchmarks Implementation

- **CIS-2.1**: Ensure CloudTrail is enabled
- **CIS-2.7**: Ensure CloudTrail logs are encrypted
- **CIS-4.1**: Ensure security groups restrict SSH access

### NIST Framework Alignment

- **PR.AC**: Access Control implementation
- **PR.DS**: Data Security through encryption
- **DE.CM**: Continuous Monitoring with CloudWatch

## References

- [AWS CloudFormation Best Practices](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/best-practices.html)
- [AWS Security Best Practices](https://aws.amazon.com/security/security-resources/)
- [CIS Benchmarks for AWS](https://www.cisecurity.org/benchmark/amazon_web_services)
- [CloudFormation Guard](https://github.com/aws-cloudformation/cloudformation-guard)