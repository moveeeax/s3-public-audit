.PHONY: install test smoke fmt clean

install:
	python -m pip install --upgrade pip
	pip install -e ".[dev]"

test:
	python -m pytest -q

smoke:
	python -m s3_public_audit scan --input examples/buckets.json --format table || true
	python -m s3_public_audit scan --input examples/buckets.json --format json

clean:
	rm -rf .pytest_cache *.egg-info build dist
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
