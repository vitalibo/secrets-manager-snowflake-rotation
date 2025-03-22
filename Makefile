PROJECT_NAME = $(shell basename $(CURDIR))

init:
	pyenv virtualenv 3.12 $(PROJECT_NAME)

install:
	pip install -r requirements.txt -r requirements-dev.txt
