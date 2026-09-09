variable "aws_region" {
  description = "AWS region for the evidence lake. Supported deploy targets: us-east-1 (commercial) and us-gov-west-1 (GovCloud). Keep this parameterized; do not hard-code the region in module resources."
  type        = string
  default     = "us-east-1"
}

variable "bucket_name" {
  description = "S3 bucket name. Empty generates beacon-evidence-<account>-<region>."
  type        = string
  default     = ""
}

variable "ddb_table_name" {
  description = "DynamoDB artifact index table name (BEACON_DDB_TABLE)."
  type        = string
  default     = "beacon-artifact-index"
}

variable "kms_alias" {
  description = "CMK alias for SSE-KMS. Default alias/beacon-evidence."
  type        = string
  default     = "alias/beacon-evidence"
}

variable "object_lock_mode" {
  description = "Default Object Lock mode. GOVERNANCE is the default (configurable retain days). COMPLIANCE is opt-in after retention days are fixed; the app does not state a long-retention period."
  type        = string
  default     = "GOVERNANCE"

  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.object_lock_mode)
    error_message = "object_lock_mode must be GOVERNANCE or COMPLIANCE."
  }
}

variable "object_lock_days" {
  description = "Object Lock retain days on new objects. Configurable because the product does not publish a fixed retention period. Default 365."
  type        = number
  default     = 365

  validation {
    condition     = var.object_lock_days >= 1
    error_message = "object_lock_days must be at least 1."
  }
}

variable "trusted_principal_arns" {
  description = "IAM principals allowed to STS-assume BeaconWriter and BeaconAuditor. Empty uses account root."
  type        = list(string)
  default     = []
}

variable "writer_role_name" {
  type    = string
  default = "BeaconWriter"
}

variable "auditor_role_name" {
  type    = string
  default = "BeaconAuditor"
}

variable "enable_instance_profile" {
  description = "Create an instance profile for BeaconWriter (optional EC2/SSM path)."
  type        = bool
  default     = false
}
