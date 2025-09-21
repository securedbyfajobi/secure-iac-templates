package terraform.s3

import rego.v1

# S3 bucket security policy
# Ensures S3 buckets have proper security configurations

default allow := false

allow if {
    input.resource_type == "aws_s3_bucket"
    has_encryption
    has_versioning
    has_public_access_block
}

has_encryption if {
    input.config.server_side_encryption_configuration[_].rule[_].apply_server_side_encryption_by_default.sse_algorithm
}

has_versioning if {
    input.config.versioning[_].enabled == true
}

has_public_access_block if {
    input.config.public_access_block[_].block_public_acls == true
    input.config.public_access_block[_].block_public_policy == true
    input.config.public_access_block[_].ignore_public_acls == true
    input.config.public_access_block[_].restrict_public_buckets == true
}

# Deny buckets with public read access
deny contains msg if {
    input.resource_type == "aws_s3_bucket"
    input.config.acl == "public-read"
    msg := "S3 bucket must not have public read access"
}

# Deny buckets without encryption
deny contains msg if {
    input.resource_type == "aws_s3_bucket"
    not has_encryption
    msg := "S3 bucket must have server-side encryption enabled"
}