packer {
  required_plugins {
    proxmox = {
      source  = "github.com/hashicorp/proxmox"
      version = "= 1.2.4"
    }
  }
}

variable "proxmox_url" {
  type = string
  validation {
    condition     = startswith(var.proxmox_url, "https://")
    error_message = "L'URL Proxmox doit utiliser HTTPS."
  }
}

variable "proxmox_username" {
  type = string
  validation {
    condition     = can(regex("^[^!]+@[^!]+![^!]+$", var.proxmox_username)) && !startswith(lower(var.proxmox_username), "root@")
    error_message = "Utilisez l'identifiant complet d'un token PVE non-root (utilisateur@realm!token)."
  }
}

variable "proxmox_token" {
  type      = string
  sensitive = true
}

variable "proxmox_node" {
  type = string
}

variable "proxmox_pool" {
  type = string
}

variable "iso_storage_pool" {
  type = string
}

variable "vm_storage_pool" {
  type = string
}

variable "bridge" {
  type    = string
  default = "vmbr0"
}

variable "template_vmid" {
  type    = number
  default = 9130
  validation {
    condition     = var.template_vmid >= 100 && var.template_vmid <= 999999999
    error_message = "Le VMID du template est hors de la plage Proxmox autorisee."
  }
}

variable "template_name" {
  type    = string
  default = "debian-13-cloudinit"
}

variable "build_username" {
  type    = string
  default = "packer"
  validation {
    condition     = can(regex("^[a-z_][a-z0-9_-]{0,30}$", var.build_username)) && !contains(["root", "admin"], var.build_username)
    error_message = "Le compte de construction doit etre un compte Linux non privilegie."
  }
}

variable "build_password" {
  type      = string
  sensitive = true
}

variable "build_password_hash" {
  type      = string
  sensitive = true
  validation {
    condition     = startswith(var.build_password_hash, "$6$")
    error_message = "Le mot de passe de construction doit etre un hash SHA-512 crypt."
  }
}

locals {
  iso_url    = "https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-13.6.0-amd64-netinst.iso"
  iso_sha256 = "65273beed27b2df543b68b65630ba525cfbad8df2b12035732b2dff87d6664e7"
}

source "proxmox-iso" "debian_13" {
  proxmox_url              = var.proxmox_url
  username                 = var.proxmox_username
  token                    = var.proxmox_token
  insecure_skip_tls_verify = false
  node                     = var.proxmox_node
  pool                     = var.proxmox_pool

  vm_id                = var.template_vmid
  vm_name              = var.template_name
  template_name        = var.template_name
  template_description = "Debian 13.6 cloud-init - ISO officielle verifiee - construit par Packer"
  tags                 = "debian-13;cloud-init;packer;managed"

  os              = "l26"
  bios            = "seabios"
  machine         = "q35"
  cpu_type        = "x86-64-v2-AES"
  cores           = 2
  memory          = 2048
  scsi_controller = "virtio-scsi-single"
  qemu_agent      = true

  boot      = "order=scsi0;ide2;net0"
  boot_wait = "10s"
  boot_command = [
    "<esc><wait>",
    "auto priority=critical preseed/url=http://{{ .HTTPIP }}:{{ .HTTPPort }}/preseed.cfg ",
    "interface=auto netcfg/get_hostname=debian-template ---<enter>"
  ]

  boot_iso {
    type         = "ide"
    index        = "2"
    iso_file     = "${var.iso_storage_pool}:iso/debian-13.6.0-amd64-netinst.iso"
    iso_checksum = "sha256:${local.iso_sha256}"
    unmount      = true
  }

  http_content = {
    "/preseed.cfg" = templatefile("${path.root}/http/preseed.cfg.pkrtpl", {
      build_username      = var.build_username
      build_password_hash = var.build_password_hash
    })
  }

  disks {
    type         = "scsi"
    disk_size    = "12G"
    storage_pool = var.vm_storage_pool
    format       = "raw"
    discard      = true
    io_thread    = true
  }

  network_adapters {
    model    = "virtio"
    bridge   = var.bridge
    firewall = true
  }

  cloud_init              = true
  cloud_init_storage_pool = var.vm_storage_pool

  communicator = "ssh"
  ssh_username = var.build_username
  ssh_password = var.build_password
  ssh_timeout  = "30m"
}

build {
  name    = "debian-13-cloudinit"
  sources = ["source.proxmox-iso.debian_13"]

  provisioner "shell" {
    environment_vars = ["BUILD_USERNAME=${var.build_username}"]
    execute_command  = "sudo -n env {{ .Vars }} bash '{{ .Path }}'"
    script           = "${path.root}/scripts/harden.sh"
  }
}
