variable "yc_token" {
  description = "Yandex Cloud OAuth token"
  type        = string
  sensitive   = true
}

variable "yc_cloud_id" {
  description = "Yandex Cloud ID"
  type        = string
}

variable "yc_folder_id" {
  description = "Yandex Cloud Folder ID"
  type        = string
}

variable "yc_zone" {
  description = "Yandex Cloud availability zone"
  type        = string
  default     = "ru-central1-a"
}

variable "ubuntu_image_id" {
  description = "Ubuntu 22.04 LTS image ID"
  type        = string
  default     = "fd8vmcue7aajpmeo39kk"  # Ubuntu 22.04 LTS
}

variable "instance_cores" {
  description = "Number of CPU cores"
  type        = number
  default     = 4
}

variable "instance_memory_gb" {
  description = "RAM in GB"
  type        = number
  default     = 8
}

variable "disk_size_gb" {
  description = "Boot disk size in GB"
  type        = number
  default     = 80
}

variable "preemptible" {
  description = "Use preemptible (spot) instance"
  type        = bool
  default     = false
}

variable "ssh_public_key" {
  description = "SSH public key for deploy user"
  type        = string
}

variable "allowed_ssh_cidrs" {
  description = "CIDR blocks allowed for SSH"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "dns_zone_id" {
  description = "Yandex Cloud DNS zone ID (optional)"
  type        = string
  default     = ""
}

variable "platform_domain" {
  description = "Domain name for the platform"
  type        = string
  default     = "security.omega-energy.ru"
}
