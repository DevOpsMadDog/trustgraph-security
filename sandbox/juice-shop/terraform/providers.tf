################################################################
# AWS provider pointed at LocalStack
#
# LocalStack exposes a single Edge port (default 4566) that
# multiplexes every AWS service endpoint. We override every
# endpoint we use so `terraform apply` talks to LocalStack
# instead of real AWS.
#
# Credentials are fake on purpose — LocalStack accepts anything.
################################################################

provider "aws" {
  region                      = var.aws_region
  access_key                  = "test"
  secret_key                  = "test"
  s3_use_path_style           = true
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true

  endpoints {
    ec2            = var.localstack_endpoint
    ecs            = var.localstack_endpoint
    ecr            = var.localstack_endpoint
    elbv2          = var.localstack_endpoint
    iam            = var.localstack_endpoint
    logs           = var.localstack_endpoint
    cloudwatch     = var.localstack_endpoint
    sts            = var.localstack_endpoint
    secretsmanager = var.localstack_endpoint
    ssm            = var.localstack_endpoint
  }

  default_tags {
    tags = {
      Project     = "trustgraph-security"
      Component   = "juice-shop-sandbox"
      ManagedBy   = "terraform"
      Environment = "localstack"
    }
  }
}
