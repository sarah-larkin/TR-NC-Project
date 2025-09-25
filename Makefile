#variables 
SHELL:=/bin/bash
PYTHONPATH=$(shell pwd)
ACTIVATE_VENV=source venv/bin/activate


define execute_in_venv
	$(ACTIVATE_VENV) && $1 
endef 

set-pythonpath: 
	export PYTHONPATH=$(PYTHONPATH)

create-environment: 
	@echo "creating virtual environment (venv)"
	python -m venv venv
	@echo "venv created"

install-requirements: create-environment
	@echo "activating venv & installing requirements to venv"
	$(call execute_in_venv, pip install -r requirements.txt) 
	@echo "requirements installed"
#TODO: check if should be using requirements.txt

#PEP 8 compliance - black, flake 8 
#security - bandit, safety 
#TODO: check other options: Auto PEP8, pip-audit, pydantic
install-dev-tools: 
	@echo "installing dev tools" 
	$(call execute_in_venv, pip install black flake8 bandit safety)
	@echo "dev tools installed"

#unit testing
unit-test: 
	$(call execute_in_venv, PYTHONPATH=$(pwd) pytest -vvrp --testdox)

security-check: 
	$(call execute_in_venv, safety check -r requirements.txt )
	$(call execute_in_venv, bandit -lll */*.py *c/*.py)
#TODO: check this  


#run
run-setup: set-pythonpath create-environment 
run-testing-security: unit-test security-check