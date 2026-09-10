.PHONY: policy test

test:
	pytest

# Conftest/OPA checks for deploy/aws. Install: https://github.com/open-policy-agent/conftest/releases
policy:
	@command -v conftest >/dev/null || { echo "Install Conftest: https://github.com/open-policy-agent/conftest/releases"; exit 1; }
	conftest verify -p policy/terraform
	conftest test --combine --parser hcl2 -p policy/terraform deploy/aws/*.tf
