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

# Exact forbidden actions. IAM Allow patterns are matched with IAM glob semantics.
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

# Service-wide Allow wildcards are too broad even when a precise allow-list also exists.
broad_allow_wildcards := {
	"*",
	"s3:*",
	"dynamodb:*",
	"kms:*",
}

writer_required_actions := {
	"s3:PutObject",
	"s3:PutObjectRetention",
	"kms:GenerateDataKey",
}

s3_object_actions := {
	"s3:GetObject",
	"s3:GetObjectVersion",
	"s3:GetObjectTagging",
	"s3:GetObjectRetention",
	"s3:PutObject",
	"s3:PutObjectTagging",
	"s3:PutObjectRetention",
	"s3:DeleteObject",
	"s3:DeleteObjectVersion",
	"s3:BypassGovernanceRetention",
}

ddb_item_actions := {
	"dynamodb:GetItem",
	"dynamodb:PutItem",
	"dynamodb:UpdateItem",
	"dynamodb:DeleteItem",
	"dynamodb:BatchGetItem",
	"dynamodb:BatchWriteItem",
	"dynamodb:Query",
	"dynamodb:Scan",
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

ref_str(x) := sprintf("%v", [x])

# IAM action matching is case-insensitive. "*" and "?" follow IAM glob rules.
iam_action_grants(pattern, action) if {
	glob.match(lower(pattern), [], lower(action))
}

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

has_evidence_bucket if {
	some item in resources_of("aws_s3_bucket")
	item.name == "evidence"
}

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

dynamic_statements(name) := [content |
	some item in data_of("aws_iam_policy_document")
	item.name == name
	dyn := item.values.dynamic
	some block in ensure_array(dyn.statement)
	is_object(block)
	some content in ensure_array(block.content)
	is_object(content)
]

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

sse_values_use_evidence_cmk(values) if {
	some rule in ensure_array(values.rule)
	is_object(rule)
	some apply in ensure_array(rule.apply_server_side_encryption_by_default)
	is_object(apply)
	apply.sse_algorithm == "aws:kms"
	contains(ref_str(apply.kms_master_key_id), "aws_kms_key.evidence")
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
	some item in resources_of("aws_s3_bucket_server_side_encryption_configuration")
	not sse_values_use_evidence_cmk(item.values)
	msg := "S3 default encryption must be SSE-KMS with aws_kms_key.evidence"
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
	item.name == "evidence"
	item.values.object_lock_enabled != true
	msg := "S3 evidence bucket must set object_lock_enabled = true"
}

deny contains msg if {
	some item in resources_of("aws_s3_bucket")
	item.name == "logs"
	item.values.object_lock_enabled == true
	msg := "Logging bucket must not enable Object Lock; S3 server access logging cannot deliver to an Object Lock destination"
}

deny contains msg if {
	has_evidence_bucket
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

# --- Bucket policy SIDs + evidence attachment ---

bucket_sid_present(sid) if sid in sids_of("bucket")

evidence_bucket_policy_attached if {
	some item in resources_of("aws_s3_bucket_policy")
	contains(ref_str(item.values.bucket), "aws_s3_bucket.evidence")
	contains(ref_str(item.values.policy), "data.aws_iam_policy_document.bucket")
}

deny contains msg if {
	has_evidence_bucket
	not evidence_bucket_policy_attached
	msg := "aws_s3_bucket_policy must attach data.aws_iam_policy_document.bucket to aws_s3_bucket.evidence"
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
	has_evidence_bucket
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

deny contains msg if {
	some stmt in statements("bucket")
	is_object(stmt)
	stmt.sid == "DenyInsecureTransport"
	not insecure_transport_denied(stmt)
	msg := "DenyInsecureTransport must deny s3:* for principal * on aws_s3_bucket.evidence when aws:SecureTransport is false"
}

insecure_transport_denied(stmt) if {
	stmt.effect == "Deny"
	some pattern in as_list(stmt.actions)
	iam_action_grants(pattern, "s3:PutObject")
	iam_action_grants(pattern, "s3:GetObject")
	some p in ensure_array(stmt.principals)
	is_object(p)
	p.type == "*"
	"*" in as_list(p.identifiers)
	some res in as_list(stmt.resources)
	contains(ref_str(res), "aws_s3_bucket.evidence")
	some cond in ensure_array(stmt.condition)
	is_object(cond)
	cond.test == "Bool"
	cond.variable == "aws:SecureTransport"
	secure_transport_is_false(cond)
}

secure_transport_is_false(cond) if {
	some v in as_list(cond.values)
	v == false
}

secure_transport_is_false(cond) if {
	some v in as_list(cond.values)
	v == "false"
}

# --- IAM Writer / Auditor ---

deny contains msg if {
	has_writer_doc
	some pattern in actions_of("writer")
	some forbidden in writer_forbidden_actions
	iam_action_grants(pattern, forbidden)
	msg := sprintf("BeaconWriter must not allow %s", [pattern])
}

deny contains msg if {
	has_auditor_doc
	some pattern in actions_of("auditor")
	some forbidden in auditor_forbidden_actions
	iam_action_grants(pattern, forbidden)
	msg := sprintf("BeaconAuditor must not allow %s", [pattern])
}

deny contains msg if {
	has_writer_doc
	some pattern in actions_of("writer")
	lower(pattern) in broad_allow_wildcards
	msg := sprintf("BeaconWriter must not allow wildcard %s", [pattern])
}

deny contains msg if {
	has_auditor_doc
	some pattern in actions_of("auditor")
	lower(pattern) in broad_allow_wildcards
	msg := sprintf("BeaconAuditor must not allow wildcard %s", [pattern])
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
	some name in {"writer", "auditor"}
	some stmt in statements(name)
	is_object(stmt)
	stmt_allows_s3_object(stmt)
	some res in as_list(stmt.resources)
	not workspace_scoped_resource(res)
	msg := sprintf("Beacon %s S3 object Allow resources must stay under local.workspace_prefix", [name])
}

stmt_allows_s3_object(stmt) if {
	stmt.effect == "Allow"
	some pattern in as_list(stmt.actions)
	some action in s3_object_actions
	iam_action_grants(pattern, action)
}

workspace_scoped_resource(res) if {
	contains(ref_str(res), "workspace_prefix")
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
	stmt_has_leading_keys(stmt)
}

stmt_has_leading_keys(stmt) if {
	some cond in ensure_array(stmt.condition)
	is_object(cond)
	cond.variable == "dynamodb:LeadingKeys"
	some value in as_list(cond.values)
	contains(ref_str(value), "ddb_pk")
}

deny contains msg if {
	some name in {"writer", "auditor"}
	some stmt in statements(name)
	is_object(stmt)
	stmt_allows_ddb_item(stmt)
	not stmt_has_leading_keys(stmt)
	msg := sprintf("Beacon %s DynamoDB item Allow statements must set dynamodb:LeadingKeys to local.ddb_pk", [name])
}

stmt_allows_ddb_item(stmt) if {
	stmt.effect == "Allow"
	some pattern in as_list(stmt.actions)
	some action in ddb_item_actions
	iam_action_grants(pattern, action)
}

deny contains msg if {
	has_writer_doc
	some stmt in dynamic_statements("writer")
	is_object(stmt)
	stmt.effect == "Allow"
	some pattern in as_list(stmt.actions)
	some forbidden in writer_forbidden_actions
	iam_action_grants(pattern, forbidden)
	msg := sprintf("BeaconWriter must not allow %s", [pattern])
}

deny contains msg if {
	has_writer_doc
	some stmt in dynamic_statements("writer")
	is_object(stmt)
	stmt.effect == "Allow"
	some pattern in as_list(stmt.actions)
	lower(pattern) in broad_allow_wildcards
	msg := sprintf("BeaconWriter must not allow wildcard %s", [pattern])
}

deny contains msg if {
	some stmt in dynamic_statements("writer")
	is_object(stmt)
	stmt_allows_s3_object(stmt)
	some res in as_list(stmt.resources)
	not workspace_scoped_resource(res)
	not lake_log_object_resource(res)
	msg := "BeaconWriter dynamic S3 object Allow resources must stay under local.workspace_prefix or the logging prefixes"
}

deny contains msg if {
	some name in {"writer", "auditor"}
	some stmt in array.concat(statements(name), dynamic_statements(name))
	is_object(stmt)
	statement_mentions_logs(stmt)
	not writer_log_read_ok(name, stmt)
	msg := sprintf("Beacon %s logging-bucket access must be read-only on the s3-access-logs/ and cloudtrail/ prefixes", [name])
}

deny contains msg if {
	has_logs_bucket
	has_writer_doc
	not writer_has_lake_log_sid("S3ListLakeLogs")
	msg := "BeaconWriter must list only the s3-access-logs/ and cloudtrail/ prefixes on the logging bucket"
}

deny contains msg if {
	has_logs_bucket
	has_writer_doc
	not writer_has_lake_log_sid("S3GetLakeLogs")
	msg := "BeaconWriter must get objects only under the s3-access-logs/ and cloudtrail/ prefixes"
}

has_logs_bucket if {
	some item in resources_of("aws_s3_bucket")
	item.name == "logs"
}

statement_mentions_logs(stmt) if {
	some res in as_list(stmt.resources)
	contains(ref_str(res), "aws_s3_bucket.logs")
}

writer_log_read_ok(name, stmt) if {
	name == "writer"
	statement_is_lake_log_read(stmt)
}

writer_has_lake_log_sid(sid) if {
	some stmt in array.concat(statements("writer"), dynamic_statements("writer"))
	is_object(stmt)
	stmt.sid == sid
	statement_is_lake_log_read(stmt)
}

statement_is_lake_log_read(stmt) if statement_is_lake_log_list(stmt)

statement_is_lake_log_read(stmt) if statement_is_lake_log_get(stmt)

statement_is_lake_log_list(stmt) if {
	stmt.effect == "Allow"
	statement_actions_are_list(stmt)
	count(as_list(stmt.resources)) > 0
	not statement_has_non_bucket_arn(stmt)
	statement_limits_log_prefixes(stmt)
}

statement_is_lake_log_get(stmt) if {
	stmt.effect == "Allow"
	statement_actions_are_get(stmt)
	count(as_list(stmt.resources)) > 0
	not statement_has_non_log_object(stmt)
	some res in as_list(stmt.resources)
	contains(ref_str(res), "s3_access_log_prefix")
	some res2 in as_list(stmt.resources)
	contains(ref_str(res2), "cloudtrail_s3_prefix")
}

statement_actions_are_list(stmt) if {
	count(as_list(stmt.actions)) > 0
	not statement_has_non_list_action(stmt)
}

statement_actions_are_get(stmt) if {
	count(as_list(stmt.actions)) > 0
	not statement_has_non_get_action(stmt)
}

statement_has_non_list_action(stmt) if {
	some pattern in as_list(stmt.actions)
	not is_list_action(pattern)
}

statement_has_non_get_action(stmt) if {
	some pattern in as_list(stmt.actions)
	not is_get_action(pattern)
}

is_list_action(pattern) if lower(pattern) in {"s3:listbucket", "s3:listbucketversions"}

is_get_action(pattern) if lower(pattern) in {"s3:getobject", "s3:getobjectversion"}

statement_has_non_bucket_arn(stmt) if {
	some res in as_list(stmt.resources)
	not lake_log_bucket_arn(res)
}

statement_has_non_log_object(stmt) if {
	some res in as_list(stmt.resources)
	not lake_log_object_resource(res)
}

lake_log_bucket_arn(res) if {
	text := ref_str(res)
	contains(text, "aws_s3_bucket.logs")
	not contains(text, "s3_access_log_prefix")
	not contains(text, "cloudtrail_s3_prefix")
	not contains(text, "/*")
}

lake_log_object_resource(res) if {
	text := ref_str(res)
	contains(text, "aws_s3_bucket.logs")
	contains(text, ".arn}/${local.s3_access_log_prefix}")
}

lake_log_object_resource(res) if {
	text := ref_str(res)
	contains(text, "aws_s3_bucket.logs")
	contains(text, ".arn}/${local.cloudtrail_s3_prefix}")
}

statement_limits_log_prefixes(stmt) if {
	some cond in ensure_array(stmt.condition)
	is_object(cond)
	cond.test == "StringLike"
	cond.variable == "s3:prefix"
	count(as_list(cond.values)) > 0
	not prefix_value_outside_logs(cond)
	some value in as_list(cond.values)
	contains(ref_str(value), "s3_access_log_prefix")
	some value2 in as_list(cond.values)
	contains(ref_str(value2), "cloudtrail_s3_prefix")
}

prefix_value_outside_logs(cond) if {
	some value in as_list(cond.values)
	text := ref_str(value)
	not contains(text, "s3_access_log_prefix")
	not contains(text, "cloudtrail_s3_prefix")
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
	contains(ref_str(enc.kms_key_arn), "aws_kms_key.evidence")
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

# --- S3 access logging + CloudTrail data events ---

deny contains msg if {
	has_evidence_bucket
	count(resources_of("aws_s3_bucket_logging")) == 0
	msg := "S3 evidence bucket must set aws_s3_bucket_logging to a dedicated logging bucket"
}

deny contains msg if {
	some item in resources_of("aws_s3_bucket_logging")
	not dedicated_log_target(item.values)
	msg := "Evidence S3 access logs must target a dedicated logging bucket (not aws_s3_bucket.evidence)"
}

dedicated_log_target(values) if {
	contains(ref_str(values.target_bucket), "aws_s3_bucket.")
	not contains(ref_str(values.target_bucket), "aws_s3_bucket.evidence")
}

deny contains msg if {
	has_evidence_bucket
	count(resources_of("aws_cloudtrail")) == 0
	msg := "Module must define aws_cloudtrail data events for the evidence bucket"
}

deny contains msg if {
	some item in resources_of("aws_cloudtrail")
	not trail_is_data_events_only(item.values)
	msg := "CloudTrail must log S3 object-level data events (read and write) for aws_s3_bucket.evidence and must not enable account-level management events"
}

trail_is_data_events_only(values) if {
	some sel in ensure_array(values.event_selector)
	is_object(sel)
	sel.read_write_type == "All"
	management_events_disabled(sel)
	some dr in ensure_array(sel.data_resource)
	is_object(dr)
	dr.type == "AWS::S3::Object"
	some v in as_list(dr.values)
	contains(ref_str(v), "aws_s3_bucket.evidence")
}

management_events_disabled(sel) if sel.include_management_events == false

management_events_disabled(sel) if sel.include_management_events == "false"

deny contains msg if {
	some item in tf_variables
	item.name == "enable_s3_access_logging"
	item.values.default != true
	msg := "var.enable_s3_access_logging default must be true"
}

deny contains msg if {
	some item in tf_variables
	item.name == "enable_cloudtrail_data_events"
	item.values.default != true
	msg := "var.enable_cloudtrail_data_events default must be true"
}
