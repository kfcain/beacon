package beacon.inventory_test
import rego.v1
import data.beacon.inventory

good := {"schema":"beacon.inventory.gate.v1","expected":[{"id":"module.storage.key","type":"aws_kms_key","checks":["KMS-ROTATE"]}],"resources":[{"id":"module.storage.key","type":"aws_kms_key","collectionStatus":"complete","facts":{"keyRotation":true}}],"ageSeconds":30,"maxAgeSeconds":3600}
test_known_good if { inventory.allow with input as good }
test_missing_population if { not inventory.allow with input as object.union(good,{"resources":[]}) }
test_empty_expected if { not inventory.allow with input as object.union(good,{"expected":[]}) }
test_stale if { not inventory.allow with input as object.union(good,{"ageSeconds":7200}) }
test_future if { not inventory.allow with input as object.union(good,{"ageSeconds":-1}) }
test_unknown if { not inventory.allow with input as object.union(good,{"resources":[object.union(good.resources[0],{"facts":{"keyRotation":null}})]}) }
test_false if { not inventory.allow with input as object.union(good,{"resources":[object.union(good.resources[0],{"facts":{"keyRotation":false}})]}) }
test_error if { not inventory.allow with input as object.union(good,{"resources":[object.union(good.resources[0],{"collectionStatus":"error"})]}) }
test_duplicate if { not inventory.allow with input as object.union(good,{"resources":[good.resources[0],good.resources[0]]}) }
