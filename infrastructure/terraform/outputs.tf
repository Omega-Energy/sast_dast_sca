output "server_ip" {
  description = "Public IP of the security platform server"
  value       = yandex_compute_instance.security_server.network_interface[0].nat_ip_address
}

output "server_id" {
  description = "Instance ID"
  value       = yandex_compute_instance.security_server.id
}

output "ssh_command" {
  description = "SSH command to connect"
  value       = "ssh deploy@${yandex_compute_instance.security_server.network_interface[0].nat_ip_address}"
}

output "platform_url" {
  description = "Platform URL"
  value       = "https://${var.platform_domain}"
}
