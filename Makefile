.PHONY: verify test

verify:
	python3 scripts/verify_release.py

test: verify
	python3 -m unittest discover -s tests -v
