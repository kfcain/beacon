# Beacon AWS evidence lake — Conftest policies.
# These rules check controls that deploy/aws already encodes.
# They do not invent controls that Terraform does not implement.
package main

import rego.v1

allowed_regions := {"us-east-1", "us-gov-west-1"}

lock_modes := {"GOVERNANCE", "COMPLIANCE"}

raw_trust_center_classes := {
	"observation",
	"finding",
	"chain-record",
	"checkpoint",
	"import",
}

required_bucket_sids := {
	"DenyInsecureTransport",
	"DenyDeleteObject",
	"DenyUnencryptedObjectUploads",
	"DenyRawInTrustCenterByClass",
	"DenyObservationsUnderTrustCenterPrefix",
}

writer_forbidden_actions := {
	"s3:DeleteObject",
	"s3:DeleteObjectVersion",
	"s3:BypassGovernanceRetention",
	"s3:*",
}

auditor_forbidden_actions := {
	"s3:PutObject",
	"s3:PutObjectTagging",
	"s3:PutObjectRetention",
	"s3:DeleteObject",
	"s3:DeleteObjectVersion",
	"s3:BypassGovernanceRetention",
	"dynamodb:PutItem",
	"dynamodb:UpdateItem",
	"dynamodb:BatchWriteItem",
	"kms:Encrypt",
	"kms:ReEncrypt*",
	"kms:GenerateDataKey",
	"kms:GenerateDataKeyWithoutPlaintext",
	"kms:CreateGrant",
	"s3:*",
	"dynamodb:DeleteItem",
	"dynamodb:DeleteTable",
}

writer_required_actions := {
	"s3:PutObject",
	"s3:PutObjectRetention",
	"kms:GenerateDataKey",
}

# Input must be Conftest --combine form: [{path, contents}, ...].
# Unit tests wrap parse_config output with as_input() in evidence_lake_test.rego.

ensure_array(x) := x if is_array(x)

ensure_array(x) := [] if is_null(x)

ensure_array(x) := [x] if {
	not is_array(x)
	not is_null(x)
}

as_list(x) := x if is_array(x)

as_list(x) := [x] if {
	not is_array(x)
	not is_null(x)
}

as_list(x) := [] if is_null(x)

hcl_docs contains doc if {
	some row in input
	doc := row.contents
	is_object(doc)
}

deny contains msg if {
	not is_array(input)
	msg := "Conftest must run with --combine so all deploy/aws files are evaluated together"
}

deny contains msg if {
	is_array(input)
	count(hcl_docs) == 0
	msg := "Combined Terraform input had no HCL documents"
}

tf_resources contains item if {
	some doc in hcl_docs
	some rtype, names in doc.resource
	is_object(names)
	some name, arr in names
	some values in ensure_array(arr)
	is_object(values)
	item := {"type": rtype, "name": name, "values": values}
}

tf_data contains item if {
	some doc in hcl_docs
	some dtype, names in doc.data
	is_object(names)
	some name, arr in names
	some values in ensure_array(arr)
	is_object(values)
	item := {"type": dtype, "name": name, "values": values}
}

tf_variables contains item if {
	some doc in hcl_docs
	some name, arr in doc.variable
	some values in ensure_array(arr)
	is_object(values)
	item := {"name": name, "values": values}
}

resources_of(rtype) := [item |
	some item in tf_resources
	item.type == rtype
]

data_of(dtype) := [item |
	some item in tf_data
	item.type == dtype
]

has_s3_bucket if count(resources_of("aws_s3_bucket")) > 0

has_kms_key if count(resources_of("aws_kms_key")) > 0

has_ddb if count(resources_of("aws_dynamodb_table")) > 0

has_writer_doc if {
	some item in data_of("aws_iam_policy_document")
	item.name == "writer"
}

has_auditor_doc if {
	some item in data_of("aws_iam_policy_document")
	item.name == "auditor"
}

policy_doc(name) := item.values if {
	some item in data_of("aws_iam_policy_document")
	item.name == name
}

statements(name) := ensure_array(policy_doc(name).statement)

actions_of(name) := {action |
	some stmt in statements(name)
	is_object(stmt)
	stmt.effect == "Allow"
	some action in as_list(stmt.actions)
}

sids_of(name) := {sid |
	some stmt in statements(name)
	is_object(stmt)
	sid := stmt.sid
}

# --- SSE-KMS ---

sse_rules contains rule if {
	some item in resources_of("aws_s3_bucket_server_side_encryption_configuration")
	some rule in ensure_array(item.values.rule)
	is_object(rule)
}

sse_uses_kms if {
	some rule in sse_rules
	some apply in ensure_array(rule.apply_server_side_encryption_by_default)
	is_object(apply)
	apply.sse_algorithm == "aws:kms"
	apply.kms_master_key_id
}

deny contains msg if {
	has_s3_bucket
	count(resources_of("aws_s3_bucket_server_side_encryption_configuration")) == 0
	msg := "S3 evidence bucket must set aws_s3_bucket_server_side_encryption_configuration"
}

deny contains msg if {
	count(sse_rules) > 0
	not sse_uses_kms
	msg := "S3 evidence bucket default encryption must be SSE-KMS (aws:kms) with a customer CMK"
}

deny contains msg if {
	has_s3_bucket
	not bucket_sid_present("DenyUnencryptedObjectUploads")
	msg := "Bucket policy must deny PutObject that is not SSE-KMS (DenyUnencryptedObjectUploads)"
}

deny contains msg if {
	some stmt in statements("bucket")
	is_object(stmt)
	stmt.sid == "DenyUnencryptedObjectUploads"
	not sse_deny_requires_kms(stmt)
	msg := "DenyUnencryptedObjectUploads must require s3:x-amz-server-side-encryption = aws:kms"
}

sse_deny_requires_kms(stmt) if {
	stmt.effect == "Deny"
	some cond in ensure_array(stmt.condition)
	is_object(cond)
	cond.test == "StringNotEquals"
	cond.variable == "s3:x-amz-server-side-encryption"
	"aws:kms" in as_list(cond.values)
}

# --- Block Public Access ---

deny contains msg if {
	has_s3_bucket
	count(resources_of("aws_s3_bucket_public_access_block")) == 0
	msg := "S3 evidence bucket must set aws_s3_bucket_public_access_block"
}

deny contains msg if {
	some item in resources_of("aws_s3_bucket_public_access_block")
	not bpa_fully_blocked(item.values)
	msg := "S3 Block Public Access must enable block_public_acls, block_public_policy, ignore_public_acls, and restrict_public_buckets"
}

bpa_fully_blocked(values) if {
	values.block_public_acls == true
	values.block_public_policy == true
	values.ignore_public_acls == true
	values.restrict_public_buckets == true
}

# --- No public ACL / bucket owner enforced ---

deny contains msg if {
	has_s3_bucket
	count(resources_of("aws_s3_bucket_ownership_controls")) == 0
	msg := "S3 evidence bucket must set ownership controls"
}

deny contains msg if {
	some item in resources_of("aws_s3_bucket_ownership_controls")
	not ownership_enforced(item.values)
	msg := "S3 object_ownership must be BucketOwnerEnforced (ACLs disabled)"
}

ownership_enforced(values) if {
	some rule in ensure_array(values.rule)
	is_object(rule)
	rule.object_ownership == "BucketOwnerEnforced"
}

deny contains msg if {
	some item in resources_of("aws_s3_bucket_acl")
	acl := item.values.acl
	acl in {"public-read", "public-read-write", "authenticated-read"}
	msg := sprintf("S3 bucket ACL %q is public; evidence lake must not use public ACLs", [acl])
}

# --- Object Lock + versioning ---

deny contains msg if {
	some item in resources_of("aws_s3_bucket")
	item.values.object_lock_enabled != true
	msg := "S3 evidence bucket must set object_lock_enabled = true"
}

deny contains msg if {
	has_s3_bucket
	count(resources_of("aws_s3_bucket_object_lock_configuration")) == 0
	msg := "S3 evidence bucket must set Object Lock default retention"
}

deny contains msg if {
	some item in resources_of("aws_s3_bucket_object_lock_configuration")
	not object_lock_mode_ok(item.values)
	msg := "Object Lock default retention mode must be GOVERNANCE, COMPLIANCE, or var.object_lock_mode"
}

object_lock_mode_ok(values) if {
	some rule in ensure_array(values.rule)
	is_object(rule)
	some ret in ensure_array(rule.default_retention)
	is_object(ret)
	ret.mode in lock_modes
}

object_lock_mode_ok(values) if {
	some rule in ensure_array(values.rule)
	is_object(rule)
	some ret in ensure_array(rule.default_retention)
	is_object(ret)
	ret.mode == "${var.object_lock_mode}"
}

deny contains msg if {
	some item in tf_variables
	item.name == "object_lock_mode"
	item.values.default != "GOVERNANCE"
	msg := "var.object_lock_mode default must be GOVERNANCE (COMPLIANCE is opt-in)"
}

deny contains msg if {
	has_s3_bucket
	count(resources_of("aws_s3_bucket_versioning")) == 0
	msg := "S3 evidence bucket must enable versioning (required for Object Lock)"
}

deny contains msg if {
	some item in resources_of("aws_s3_bucket_versioning")
	not versioning_enabled(item.values)
	msg := "S3 versioning_configuration.status must be Enabled"
}

versioning_enabled(values) if {
	some cfg in ensure_array(values.versioning_configuration)
	is_object(cfg)
	cfg.status == "Enabled"
}

# --- Lifecycle IA / Glacier ---

deny contains msg if {
	has_s3_bucket
	count(resources_of("aws_s3_bucket_lifecycle_configuration")) == 0
	msg := "S3 evidence bucket must set lifecycle transitions to STANDARD_IA and GLACIER"
}

deny contains msg if {
	count(resources_of("aws_s3_bucket_lifecycle_configuration")) > 0
	not lifecycle_has_class("STANDARD_IA", 90)
	msg := "Lifecycle must transition tagged objects to STANDARD_IA at 90 days"
}

deny contains msg if {
	count(resources_of("aws_s3_bucket_lifecycle_configuration")) > 0
	not lifecycle_has_class("GLACIER", 365)
	msg := "Lifecycle must transition tagged objects to GLACIER at 365 days"
}

lifecycle_has_class(storage_class, days) if {
	some item in resources_of("aws_s3_bucket_lifecycle_configuration")
	some block in ensure_array(item.values.dynamic.rule)
	is_object(block)
	some content in ensure_array(block.content)
	is_object(content)
	some t in ensure_array(content.transition)
	is_object(t)
	t.storage_class == storage_class
	t.days == days
}

lifecycle_has_class(storage_class, days) if {
	some item in resources_of("aws_s3_bucket_lifecycle_configuration")
	some rule in ensure_array(item.values.rule)
	is_object(rule)
	some t in ensure_array(rule.transition)
	is_object(t)
	t.storage_class == storage_class
	t.days == days
}

# --- Bucket policy SIDs ---

bucket_sid_present(sid) if sid in sids_of("bucket")

deny contains msg if {
	has_s3_bucket
	count(resources_of("aws_s3_bucket_policy")) == 0
	msg := "S3 evidence bucket must attach aws_s3_bucket_policy"
}

deny contains msg if {
	some sid in required_bucket_sids
	some stmt in statements("bucket")
	is_object(stmt)
	stmt.sid == sid
	stmt.effect != "Deny"
	msg := sprintf("Bucket policy statement %s must have effect Deny", [sid])
}

deny contains msg if {
	has_s3_bucket
	some sid in required_bucket_sids
	not bucket_sid_present(sid)
	msg := sprintf("Bucket policy must include statement %s", [sid])
}

deny contains msg if {
	some stmt in statements("bucket")
	is_object(stmt)
	stmt.sid == "DenyDeleteObject"
	not delete_object_denied(stmt)
	msg := "DenyDeleteObject must deny s3:DeleteObject and s3:DeleteObjectVersion"
}

delete_object_denied(stmt) if {
	stmt.effect == "Deny"
	{"s3:DeleteObject", "s3:DeleteObjectVersion"} - {a | some a in as_list(stmt.actions)} == set()
}

deny contains msg if {
	some stmt in statements("bucket")
	is_object(stmt)
	stmt.sid == "DenyRawInTrustCenterByClass"
	not trust_center_class_deny(stmt)
	msg := "DenyRawInTrustCenterByClass must deny PutObject of raw beacon-class tags under public/trust-center/"
}

trust_center_class_deny(stmt) if {
	stmt.effect == "Deny"
	"s3:PutObject" in as_list(stmt.actions)
	some res in as_list(stmt.resources)
	contains(res, "public/trust-center")
	some cond in ensure_array(stmt.condition)
	is_object(cond)
	cond.variable == "s3:RequestObjectTag/beacon-class"
	raw_trust_center_classes == {c | some c in as_list(cond.values)}
}

# --- IAM Writer / Auditor ---

deny contains msg if {
	has_writer_doc
	some action in actions_of("writer")
	action in writer_forbidden_actions
	msg := sprintf("BeaconWriter must not allow %s", [action])
}

deny contains msg if {
	has_auditor_doc
	some action in actions_of("auditor")
	action in auditor_forbidden_actions
	msg := sprintf("BeaconAuditor must not allow %s", [action])
}

deny contains msg if {
	has_writer_doc
	some required in writer_required_actions
	not required in actions_of("writer")
	msg := sprintf("BeaconWriter must allow %s", [required])
}

deny contains msg if {
	has_writer_doc
	not writer_scoped_to_workspace
	msg := "BeaconWriter S3 object access must be limited to local.workspace_prefix (not bucket /*)"
}

writer_scoped_to_workspace if {
	some stmt in statements("writer")
	is_object(stmt)
	stmt.sid == "S3PutGetNoDelete"
	some res in as_list(stmt.resources)
	contains(res, "workspace_prefix")
	not endswith(res, ".arn}/*")
}

deny contains msg if {
	has_writer_doc
	not leading_keys_bound("writer")
	msg := "BeaconWriter DynamoDB writes must use dynamodb:LeadingKeys for the tenant/workspace partition"
}

deny contains msg if {
	has_auditor_doc
	not leading_keys_bound("auditor")
	msg := "BeaconAuditor DynamoDB reads must use dynamodb:LeadingKeys for the tenant/workspace partition"
}

leading_keys_bound(name) if {
	some stmt in statements(name)
	is_object(stmt)
	some cond in ensure_array(stmt.condition)
	is_object(cond)
	cond.variable == "dynamodb:LeadingKeys"
	some value in as_list(cond.values)
	contains(value, "ddb_pk")
}

# --- KMS rotation ---

deny contains msg if {
	has_kms_key
	some item in resources_of("aws_kms_key")
	item.values.enable_key_rotation != true
	msg := "Evidence lake CMK must set enable_key_rotation = true"
}

# --- DynamoDB encryption + freshness GSI ---

deny contains msg if {
	has_ddb
	some item in resources_of("aws_dynamodb_table")
	not ddb_encrypted_with_cmk(item.values)
	msg := "DynamoDB artifact index must enable SSE with the evidence CMK"
}

ddb_encrypted_with_cmk(values) if {
	some enc in ensure_array(values.server_side_encryption)
	is_object(enc)
	enc.enabled == true
	enc.kms_key_arn
}

deny contains msg if {
	has_ddb
	some item in resources_of("aws_dynamodb_table")
	not freshness_gsi(item.values)
	msg := "DynamoDB artifact index must define GSI freshness on pk + expires_at"
}

freshness_gsi(values) if {
	some gsi in ensure_array(values.global_secondary_index)
	is_object(gsi)
	gsi.name == "freshness"
	gsi.hash_key == "pk"
	gsi.range_key == "expires_at"
}

# --- Regions: provider uses var.aws_region; default is a supported region ---

deny contains msg if {
	some doc in hcl_docs
	some prov in ensure_array(doc.provider.aws)
	is_object(prov)
	region := prov.region
	region != "${var.aws_region}"
	not region in allowed_regions
	msg := sprintf("AWS provider region must be var.aws_region or an allowed region; found %q", [region])
}

deny contains msg if {
	some item in tf_variables
	item.name == "aws_region"
	not item.values.default in allowed_regions
	msg := "var.aws_region default must be us-east-1 or us-gov-west-1"
}

# Warn only: Terraform does not validate aws_region at apply time.
warn contains msg if {
	some item in tf_variables
	item.name == "aws_region"
	not variable_has_region_validation(item.values)
	msg := "Gap: var.aws_region has no validation block for us-east-1 / us-gov-west-1"
}

variable_has_region_validation(values) if {
	some v in ensure_array(values.validation)
	is_object(v)
	contains(v.condition, "us-east-1")
	contains(v.condition, "us-gov-west-1")
}

# Warn only: writer tags findings as finding; cold_classes also lists evidence.
warn contains msg if {
	some doc in hcl_docs
	some loc in ensure_array(doc.locals)
	is_object(loc)
	some class in as_list(loc.cold_classes)
	class == "evidence"
	msg := "Gap: locals.cold_classes includes evidence, but the writer tags derived records as finding"
}
