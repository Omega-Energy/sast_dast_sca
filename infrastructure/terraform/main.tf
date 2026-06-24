terraform {
  required_version = ">= 1.5.0"

  required_providers {
    yandex = {
      source  = "yandex-cloud/yandex"
      version = ">= 0.100.0"
    }
  }
}

provider "yandex" {
  token     = var.yc_token
  cloud_id  = var.yc_cloud_id
  folder_id = var.yc_folder_id
  zone      = var.yc_zone
}

# ── Network ──────────────────────────────────────────────────────────────────

resource "yandex_vpc_network" "security_net" {
  name = "security-platform-network"
}

resource "yandex_vpc_subnet" "security_subnet" {
  name           = "security-platform-subnet"
  zone           = var.yc_zone
  network_id     = yandex_vpc_network.security_net.id
  v4_cidr_blocks = ["10.10.0.0/24"]
}

# ── Security Group ───────────────────────────────────────────────────────────

resource "yandex_vpc_security_group" "security_sg" {
  name       = "security-platform-sg"
  network_id = yandex_vpc_network.security_net.id

  ingress {
    description    = "SSH"
    port           = 22
    protocol       = "TCP"
    v4_cidr_blocks = var.allowed_ssh_cidrs
  }

  ingress {
    description    = "HTTP"
    port           = 80
    protocol       = "TCP"
    v4_cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description    = "HTTPS"
    port           = 443
    protocol       = "TCP"
    v4_cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description    = "Allow all outbound"
    protocol       = "ANY"
    v4_cidr_blocks = ["0.0.0.0/0"]
  }
}

# ── Compute Instance ─────────────────────────────────────────────────────────

resource "yandex_compute_instance" "security_server" {
  name        = "security-platform"
  platform_id = "standard-v3"
  zone        = var.yc_zone

  resources {
    cores         = var.instance_cores
    memory        = var.instance_memory_gb
    core_fraction = 100
  }

  boot_disk {
    initialize_params {
      image_id = var.ubuntu_image_id
      size     = var.disk_size_gb
      type     = "network-ssd"
    }
  }

  network_interface {
    subnet_id          = yandex_vpc_subnet.security_subnet.id
    nat                = true
    security_group_ids = [yandex_vpc_security_group.security_sg.id]
  }

  metadata = {
    user-data = templatefile("${path.module}/cloud-init.yml", {
      ssh_public_key = var.ssh_public_key
      deploy_user    = "deploy"
    })
  }

  scheduling_policy {
    preemptible = var.preemptible
  }

  tags = {
    environment = "production"
    service     = "security-platform"
  }
}

# ── DNS (optional) ───────────────────────────────────────────────────────────

resource "yandex_dns_recordset" "security_a" {
  count   = var.dns_zone_id != "" ? 1 : 0
  zone_id = var.dns_zone_id
  name    = var.platform_domain
  type    = "A"
  ttl     = 300
  data    = [yandex_compute_instance.security_server.network_interface[0].nat_ip_address]
}
