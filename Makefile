REPORTER ?= dot

DEVPACK := webpack-dev-server
WEBPACK := webpack
ESLINT := eslint

WFLAGS = --progress --colors
SRC = $(shell find lib -name "*.js" -type f | sort)

all: build

start:
	$(DEVPACK) $(WFLAGS)

build: build-node build-web

build-node:
	babel --presets es2015 -d lib/ src/

build-web:
	$(WEBPACK) $(WFLAGS)

clean:
	rm -rf lib

test: lint test-unit

test-unit:
	mocha \
		-R $(REPORTER) \
		-u qunit \
		--require test/helpers/dom.js \
		--compilers js:babel-core/register

lint:
	$(ESLINT) $(SRC)
