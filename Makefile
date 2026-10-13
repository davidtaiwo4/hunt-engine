.PHONY: test build clean

INPUT ?= source
OUT_DB ?= clean.db

# make test — runs the full pytest suite (ingest, normalize, clock, identity)
test:
	python3 -m pytest -v

# make build INPUT=<path> — runs the real ingestion+normalization pipeline
# against the given input directory, producing clean.db, quarantine.csv,
# reconciliation.json, results.json in the current working directory.
build:
	python3 -m src.cli --input $(INPUT) --out $(OUT_DB)

# make clean — wipes generated artifacts so build can be re-run from empty state
clean:
	rm -f clean.db results.json quarantine.csv reconciliation.json
