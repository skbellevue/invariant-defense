.PHONY: install dev test lint fmt demo rules db-test docker clean

install:
	pip install .

dev:
	pip install -e ".[dev]"

test:
	pytest -o addopts="" -q

lint:
	ruff check src tests

fmt:
	ruff format src tests
	ruff check --fix src tests

demo:
	invariant demo --respond

rules:
	python -c "import yara,glob; [yara.compile(filepath=f) or print('ok', f) for f in glob.glob('rules/yara/*.yar')]"
	python -c "import glob; from sigma.collection import SigmaCollection as S; [print('ok', f) for f in glob.glob('rules/sigma/*.yml') if not [e for r in S.from_yaml(open(f).read()).rules for e in r.errors]]"

db-test:
	tests/sql/test_postgres_guard.sh
	tests/sql/test_mysql_guard.sh

docker:
	docker build -t invariant-defense .
	docker run --rm invariant-defense demo --respond

clean:
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache approvals snapshots restore-test
	find . -name __pycache__ -prune -exec rm -rf {} +
