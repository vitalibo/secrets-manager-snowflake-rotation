PROJECT_NAME = $(shell basename $(CURDIR))
PYTHON_VERSION = 3.12

init:
	pyenv virtualenv $(PYTHON_VERSION) $(PROJECT_NAME)

install:
	pip install -r requirements.txt -r requirements-dev.txt

codestyle:
	isort lambda*.py -l 120 -m 3
	wget -q 'https://raw.githubusercontent.com/vitalibo/pylint-rules/master/.pylintrc' -O .pylintrc
	pylint lambda*.py --rcfile .pylintrc --disable=C0209

test:
	pytest -v -p no:cacheprovider --disable-warnings ./lambda_test.py

build:
	./build.sh $(PYTHON_VERSION)

deploy:
	./deploy.sh

clean:
	rm -rf ./.pytest_cache ./build ./dist ./target ./.pylintrc

.PHONY: init install codestyle test build deploy
