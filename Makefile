.PHONY: help test eval install clean

help:
	@echo "VALKYRIE — targets:"
	@echo "  make test     Run the full test suite (pytest)"
	@echo "  make eval     Run the accuracy-harness self-test and print ACCURACY.md"
	@echo "  make install  Run the SIFT Workstation installer"
	@echo "  make clean    Remove caches and eval scratch output"

test:
	pytest tests/ -v

eval:
	python eval/run_eval.py \
		--findings eval/examples/example-findings.json \
		--truth eval/examples/example-truth.json \
		--out /tmp/valkyrie-eval
	@echo "----------------------------------------"
	@cat /tmp/valkyrie-eval/ACCURACY.md

install:
	./install.sh

clean:
	rm -rf /tmp/valkyrie-eval .pytest_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
