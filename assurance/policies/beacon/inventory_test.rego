package beacon.inventory_test
import rego.v1
import data.beacon.inventory

good := {"schema":"beacon.inventory.gate.v1","expected":[{"id":"module.storage.key","type":"aws_kms_key","checks":["KMS-ROTATE"]}],"resources":[{"id":"module.storage.key","type":"aws_kms_key","collectionStatus":"complete","facts":{"keyRotation":true}}],"ageSeconds":30,"maxAgeSeconds":3600}
test_known_good if { inventory.configuration_pass with input as good }
test_missing_population if { not inventory.configuration_pass with input as object.union(good,{"resources":[]}) }
test_empty_expected if { not inventory.configuration_pass with input as object.union(good,{"expected":[]}) }
test_stale if { not inventory.configuration_pass with input as object.union(good,{"ageSeconds":7200}) }
test_future if { not inventory.configuration_pass with input as object.union(good,{"ageSeconds":-1}) }
test_unknown if { not inventory.configuration_pass with input as object.union(good,{"resources":[object.union(good.resources[0],{"facts":{"keyRotation":null}})]}) }
test_false if { not inventory.configuration_pass with input as object.union(good,{"resources":[object.union(good.resources[0],{"facts":{"keyRotation":false}})]}) }
test_error if { not inventory.configuration_pass with input as object.union(good,{"resources":[object.union(good.resources[0],{"collectionStatus":"error"})]}) }
test_duplicate if { not inventory.configuration_pass with input as object.union(good,{"resources":[good.resources[0],good.resources[0]]}) }

test_check_type_mismatch if { not inventory.configuration_pass with input as object.union(good,{"expected":[object.union(good.expected[0],{"type":"aws_lambda_function"})],"resources":[object.union(good.resources[0],{"type":"aws_lambda_function"})]}) }

test_unverified_provenance_cannot_authorize if {
 candidate := object.union(good,{"context":{"provenance":"UNVERIFIED_IMPORT"}})
 inventory.configuration_pass with input as candidate
 not inventory.allow with input as candidate
}
test_simulated_provenance_cannot_authorize if { not inventory.allow with input as object.union(good,{"context":{"provenance":"SIMULATED"}}) }
test_self_asserted_provenance_cannot_authorize if { not inventory.allow with input as object.union(good,{"context":{"provenance":"VERIFIED","admitted":true}}) }
test_missing_provenance_cannot_authorize if { not inventory.allow with input as good }
