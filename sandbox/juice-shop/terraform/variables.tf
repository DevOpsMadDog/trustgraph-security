variable "aws_region" {
  description = "AWS region (LocalStack ignores this but the provider requires it)"
  type        = string
  default     = "us-east-1"
}

variable "localstack_endpoint" {
  description = "LocalStack edge endpoint"
  type        = string
  default     = "http://localhost:4566"
}

variable "project_name" {
  description = "Name prefix for all resources"
  type        = string
  default     = "tgs-juice-shop"
}

variable "container_image" {
  description = "Container image for Juice Shop. Default = official upstream image."
  type        = string
  default     = "bkimminich/juice-shop:v17.3.0"
}

variable "container_port" {
  description = "Port exposed by the Juice Shop container"
  type        = number
  default     = 3000
}

variable "desired_count" {
  description = "Number of Fargate tasks to run"
  type        = number
  default     = 1
}

variable "task_cpu" {
  description = "Fargate task CPU (256 = .25 vCPU)"
  type        = number
  default     = 512
}

variable "task_memory" {
  description = "Fargate task memory (MiB)"
  type        = number
  default     = 1024
}

variable "vpc_cidr" {
  type    = string
  default = "10.20.0.0/16"
}

variable "public_subnet_cidrs" {
  type    = list(string)
  default = ["10.20.1.0/24", "10.20.2.0/24"]
}

variable "azs" {
  type    = list(string)
  default = ["us-east-1a", "us-east-1b"]
}
