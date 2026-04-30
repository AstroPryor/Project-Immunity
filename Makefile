.PHONY: help install scan bandit semgrep audit secrets shellcheck yaml-check clean

help:
	@echo "Project Immunity - Static Analysis Commands"
	@echo ""
	@echo "Available commands:"
	@echo "  make install     Install Python dependencies"
	@echo "  make scan        Run all security/static checks"
	@echo "  make bandit      Scan Python code for security issues"
	@echo "  make semgrep     Run Semgrep static analysis"
	@echo "  make audit       Audit Python dependencies"
	@echo "  make secrets     Scan for leaked secrets"
	@echo "  make yaml-check  Check config.yaml for obvious unsafe values"
	@echo "  make clean       Remove generated reports"

install:
	python -m pip install -r requirements.txt
	python -m pip install bandit semgrep pip-audit

scan: bandit semgrep audit secrets yaml-check

bandit:
	bandit -r . -f txt -o bandit-results.txt || true
	@echo "Bandit results saved to bandit-results.txt"

semgrep:
	semgrep scan --config auto . --output semgrep-results.txt || true
	@echo "Semgrep results saved to semgrep-results.txt"

audit:
	pip-audit -r requirements.txt -f json -o pip-audit-results.json || true
	@echo "pip-audit results saved to pip-audit-results.json"

secrets:
	gitleaks detect --source . --report-format json --report-path gitleaks-results.json || true
	@echo "Gitleaks results saved to gitleaks-results.json"

yaml-check:
	@echo "Checking config.yaml for risky settings..."
	@grep -nEi "token|password|secret|key|admin|debug|localhost|0.0.0.0|allow|disable|false|true" config.yaml > yaml-check-results.txt || true
	@echo "YAML check results saved to yaml-check-results.txt"

clean:
	rm -f bandit-results.txt
	rm -f semgrep-results.txt
	rm -f pip-audit-results.json
	rm -f gitleaks-results.json
	rm -f yaml-check-results.txt
