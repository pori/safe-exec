REPORTER ?= dot

DEVPACK := webpack-dev-server
WEBPACK := webpack
ESLINT := eslint

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
	mocha \
		-R $(REPORTER) \
		-u qunit \
		--require test/helpers/dom.js \
		--compilers js:babel-core/register

lint:
	$(ESLINT) $(SRC)

test: lint test-unit
