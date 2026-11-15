.PHONY: test manifest
test:
	python3 -m unittest discover -s tests -v
manifest:
	bash scripts/make-fixture-registry.sh
	bash scripts/make-manifest.sh
