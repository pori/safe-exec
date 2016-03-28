REPORTER ?= dot

DEVPACK := node_modules/.bin/webpack-dev-server
WEBPACK := node_modules/.bin/webpack
ESLINT := node_modules/.bin/eslint

WFLAGS = --progress --colors
SRC = $(shell find lib -name "*.js" -type f | sort)

all: build

start:
	$(DEVPACK) $(WFLAGS)

build:
	$(WEBPACK) $(WFLAGS)

clean:
	rm -rf lib

test-unit:
	@./node_modules/.bin/_mocha \
		-R $(REPORTER) \
		-u qunit \
		--require test/helpers/dom.js

lint:
	$(ESLINT) $(SRC)

test: lint test-unit
