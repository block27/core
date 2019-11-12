RED=\033[0;31m
GRE=\033[0;32m
RES=\033[0m
MAG=\033[0;35m
CYN=\033[0;36m
RL1=\033[0;41m
BL1=\033[0;44m

GO_SRC_DIRS := $(shell \
	find . -name "*.go" -not -path "./vendor/*" | \
	xargs -I {} dirname {}  | \
	uniq)

GO_TEST_DIRS := $(shell \
	find . -name "*_test.go" -not -path "./vendor/*" | \
	xargs -I {} dirname {}  | \
	uniq)

# OK to be modified
ENVIRONMENT?=develop
NAMESPACE?=default

ifeq ($(ENVIRONMENT), develop)
	NAMESPACE = develop
endif

.EXPORT_ALL_VARIABLES:

all: configuration

# Aliases
b: build
t: test

build:
	go build -o bin/sigma-cli main.go

code_show:
	@echo "SRC  = $(GO_SRC_DIRS)"
	@echo "TEST = $(GO_TEST_DIRS)"

configuration:
	@echo "---------------------------------------------------------------------"
	@echo "${MAG}ENV${RES}[${RL1}KEY${RES}]: \t[${GRE}${KEY}${RES}]"
	@echo "${CYN}EXT${RES}[${RL1}KEY${RES}]: \t[${GRE}$(shell cat /var/data/key)${RES}]"
	@echo "${MAG}ENV${RES}[${BL1}IV${RES}]: \t[${GRE}${IV}${RES}]"
	@echo "${CYN}EXT${RES}[${BL1}IV${RES}]: \t[${GRE}$(shell cat /var/data/iv)${RES}]"
	@echo "---------------------------------------------------------------------"

ctags:
	@echo "Generating application ctags..."
	@gotags -tag-relative=true -R=true -sort=true -f="tags" -fields=+l .

ecdsa_generate:
	openssl ecparam -genkey -name secp256k1 -out privkey.pem
	openssl ec -in privkey.pem -pubout -out pubkey.pem

ecdsa_generate_rand:
	# https://hexdocs.pm/jose/key-generation.html
	openssl ecparam -name secp384r1 -rand xkcd221random.bin 2>/dev/null
	openssl ecparam -name secp521r1 -genkey -noout -rand ~/1049376.bin -out ec-secp521r1.pem

lint:
	golint ./...

openssl_cpu_speed:
	openssl speed -elapsed aes-128-cbc

openssl_hardware_accelerated:
	openssl speed -elapsed -evp aes-128-cbc

openssl_check:
	openssl asn1parse -inform der -in signature.der

openssl_sign:
	openssl dgst -sha1 -sign private.pem < file.data > signature.bin

openssl_verify:
	openssl dgst -ecdsa-with-SHA1 -verify public.pem -signature signature.bin file.data

prepare_tests:
	@rm -rf /tmp/var/keys/* || true

setup_machine:
	mkdir -p /tmp/data
	mkdir -p /var/data

# TESTING ----------------------------------------------------------------------
test: test_richgo

test_coverage_func:
	@go tool cover -func=coverage.out

test_coverage_html:
	@go tool cover -html=coverage.out

test_golang: prepare_tests
	@go test -v ./... -cover -coverprofile=coverage.out -bench=.

test_gotest: prepare_tests
	@gotest -v ./... -cover -coverprofile=coverage.out -bench=.

test_richgo: prepare_tests
	@richgo test -v ./... -cover -coverprofile=coverage.out -bench=.
