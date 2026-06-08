output "alb_dns_name" {
  description = "ALB DNS — point pentest tools here. On LocalStack resolve via the localstack container."
  value       = aws_lb.this.dns_name
}

output "alb_url" {
  description = "Convenience URL"
  value       = "http://${aws_lb.this.dns_name}"
}

output "cluster_name" {
  value = aws_ecs_cluster.this.name
}

output "service_name" {
  value = aws_ecs_service.this.name
}

output "log_group" {
  value = aws_cloudwatch_log_group.this.name
}
