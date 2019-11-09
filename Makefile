RED=\033[0;31m
GRE=\033[0;32m
RES=\033[0m
MAG=\033[0;35m
CYN=\033[0;36m
RL1=\033[0;41m
BL1=\033[0;44m

# OK to be modified
ENVIRONMENT?=develop
NAMESPACE?=default

ifeq ($(ENVIRONMENT), develop)
	NAMESPACE = develop
endif

.EXPORT_ALL_VARIABLES:

all: configuration

build:
	go build -o bin/sigma-cli main.go

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

run:
	@go run main.go

prepare_tests:
	@rm -rf /tmp/var/keys/* || true

setup_machine:
	mkdir -p /tmp/data
	mkdir -p /var/data

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
	@richgo test ./... -v -cover -coverprofile=coverage.out -bench=.
