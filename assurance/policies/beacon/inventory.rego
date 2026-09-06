# These are narrow configuration assertions, not whole-control conclusions.
package beacon.inventory
import rego.v1

fields := {"S3-KMS": ["encryptionAlgorithm", "kmsKeyArn"], "S3-VERSION": ["versioning"], "KMS-ROTATE": ["keyRotation"], "LAMBDA-TRACE": ["tracing"], "API-LOG": ["logging"]}

default allow := false
allow if {
 input.schema == "beacon.inventory.gate.v1"
 is_array(input.expected)
 count(input.expected) > 0
 is_array(input.resources)
 is_number(input.ageSeconds)
 input.ageSeconds >= 0
 is_number(input.maxAgeSeconds)
 input.maxAgeSeconds > 0
 input.ageSeconds <= input.maxAgeSeconds
 every e in input.expected {
  is_string(e.id)
  is_string(e.type)
  is_array(e.checks)
  count(e.checks) > 0
 }
 every r in input.resources {
  is_string(r.id)
  is_string(r.type)
  is_object(r.facts)
  r.collectionStatus == "complete"
 }
 count(deny) == 0
}

deny contains "Expected resource population is missing or empty" if { count(object.get(input,"expected",[])) == 0 }
deny contains sprintf("Missing or duplicated expected resource: %s", [e.id]) if {
 some e in input.expected
 matches := [r | some r in input.resources; r.id == e.id]
 count(matches) != 1
}
deny contains "Duplicate expected IDs" if { count({e.id | some e in input.expected}) != count(input.expected) }
deny contains sprintf("Unregistered resource: %s", [r.id]) if { some r in input.resources; not registered(r.id) }
registered(id) if { some e in input.expected; e.id == id }
deny contains sprintf("No implemented checks: %s", [e.id]) if { some e in input.expected; count(e.checks) == 0 }
deny contains sprintf("Unknown check: %s", [id]) if { some e in input.expected; some id in e.checks; not fields[id] }
deny contains sprintf("Invalid resource observation: %s", [e.id]) if { some e in input.expected; some r in input.resources; r.id == e.id; r.type != e.type }
deny contains sprintf("Collection incomplete: %s", [r.id]) if { some r in input.resources; r.collectionStatus != "complete" }
deny contains sprintf("Unknown required fact: %s / %s", [e.id,key]) if { some e in input.expected; some r in input.resources; r.id == e.id; some id in e.checks; some key in fields[id]; object.get(r.facts,key,null) == null }
deny contains sprintf("Assertion failed: %s / %s", [e.id,id]) if { some e in input.expected; some r in input.resources; r.id == e.id; some id in e.checks; not satisfies(id,r.facts) }
deny contains "Evidence is stale or future-dated" if { input.ageSeconds > input.maxAgeSeconds }
deny contains "Evidence is stale or future-dated" if { input.ageSeconds < 0 }

satisfies("S3-KMS",f) if { f.encryptionAlgorithm == "aws:kms"; regex.match(`^arn:aws(-us-gov|-cn)?:kms:[a-z0-9-]+:[0-9]{12}:key/[a-zA-Z0-9-]+$`,f.kmsKeyArn) }
satisfies("S3-VERSION",f) if { f.versioning == "Enabled" }
satisfies("KMS-ROTATE",f) if { f.keyRotation == true }
satisfies("LAMBDA-TRACE",f) if { f.tracing == "Active" }
satisfies("API-LOG",f) if { startswith(f.logging,"arn:"); contains(f.logging,":logs:") }
