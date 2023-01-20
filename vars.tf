variable "AWS_REGION" {
  type        = string
  default     = "us-east-1"
  description = "AWS region"
}

variable "AWS_AMI" {
  type        = string
  default     = "ami-03a45a5ac837f33b7"
  description = "AWS instance AMI"
}

variable "SSH_PUBLIC_KEY" {
  type        = string
  default     = "sshkey.pub"
  description = "SSH public key location"
}