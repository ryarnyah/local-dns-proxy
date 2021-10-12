# Set an output prefix, which is the local directory if not specified
PREFIX?=$(shell pwd)

# Setup name variables for the package/tool
BASE_REPOSITORY := ryarnyah
BINARIES := local-dns-proxy
BASE_PKG := github.com/$(BASE_REPOSITORY)
BASE_BINARIES := .

# Set any default go build tags
BUILDTAGS := 

# Set the build dir, where built cross-compiled binaries will be output
BASE_BUILD_DIR := build
BUILDDIR := ${PREFIX}/${BASE_BUILD_DIR}

# Populate version variables
# Add to compile time flags
VERSION := $(shell cat VERSION.txt)
GITCOMMIT := $(shell git rev-parse --short HEAD)
GITUNTRACKEDCHANGES := $(shell git status --porcelain --untracked-files=no)
ifneq ($(GITUNTRACKEDCHANGES),)
	GITCOMMIT := $(GITCOMMIT)-dirty
endif
CTIMEVAR=-X $(BASE_PKG)/$(1)/version.GITCOMMIT=$(GITCOMMIT) -X $(BASE_PKG)/$(1)/version.VERSION=$(VERSION)
GO_LDFLAGS=-ldflags "-s -w $(call CTIMEVAR,$(1))"
GO_LDFLAGS_STATIC=-ldflags "-s -w $(call CTIMEVAR,$(1)) -extldflags -static"

# List the GOOS and GOARCH to build
GOOSARCHES = linux/arm linux/amd64 linux/arm64 windows/amd64 windows/386

all: clean build fmt lint test staticcheck vet ## Runs a clean, build, fmt, lint, test, staticcheck, vet

.PHONY: build
build: $(BINARIES) ## Builds a dynamic executable or package

$(BINARIES): VERSION.txt
	@echo "+ $@"
	GO111MODULE=on CGO_ENABLED=0 go build -tags "$(BUILDTAGS)" $(call GO_LDFLAGS,$@) -o $@ $(BASE_BINARIES)

.PHONY: static
static: ## Builds a static executable
	@echo "+ $@"
	$(foreach BINARY,$(BINARIES),GO111MODULE=on CGO_ENABLED=0 go build -tags "$(BUILDTAGS) static_build" $(call GO_LDFLAGS_STATIC $(BINARY)) -o $(BINARY) $(BASE_BINARIES)/$(BINARY))

.PHONY: fmt
fmt: ## Verifies all files have men `gofmt`ed
	@echo "+ $@"
	@gofmt -s -l . | grep -v '.pb.go:' | grep -v vendor | tee /dev/stderr

.PHONY: lint
lint: ## Verifies `golint` passes
	@echo "+ $@"
	@golint ./... | grep -v '.pb.go:' | grep -v vendor | tee /dev/stderr

.PHONY: test
test: ## Runs the go tests
	@echo "+ $@"
	@go test -v -tags "$(BUILDTAGS) cgo" $(shell go list ./... | grep -v vendor)

.PHONY: vet
vet: ## Verifies `go vet` passes
	@echo "+ $@"
	@go vet $(shell go list ./... | grep -v vendor) | grep -v '.pb.go:' | tee /dev/stderr

.PHONY: staticcheck
staticcheck: ## Verifies `staticcheck` passes
	@echo "+ $@"
	@staticcheck $(shell go list ./... | grep -v vendor) | grep -v '.pb.go:' | tee /dev/stderr

.PHONY: cover
cover: ## Runs go test with coverage
	@echo "" > coverage.txt
	@for d in $(shell go list ./... | grep -v vendor); do \
		go test -race -coverprofile=profile.out -covermode=atomic "$$d"; \
		if [ -f profile.out ]; then \
			cat profile.out >> coverage.txt; \
			rm profile.out; \
		fi; \
	done;

define buildpretty
mkdir -p $(BUILDDIR)/$(1)/$(2);
GOOS=$(1) GOARCH=$(2) GO111MODULE=on CGO_ENABLED=0 go build \
	 -o $(BUILDDIR)/$(1)/$(2)/$(3)$(if $(findstring windows, $(1)),.exe) \
	 -a -tags "$(BUILDTAGS) static_build netgo" \
	 -installsuffix netgo $(call GO_LDFLAGS_STATIC,$3) $(BASE_BINARIES)/$(3);
md5sum $(BUILDDIR)/$(1)/$(2)/$(3)$(if $(findstring windows, $(1)),.exe) > $(BUILDDIR)/$(1)/$(2)/$(3)$(if $(findstring windows, $(1)),.exe).md5;
sha256sum $(BUILDDIR)/$(1)/$(2)/$(3)$(if $(findstring windows, $(1)),.exe) > $(BUILDDIR)/$(1)/$(2)/$(3)$(if $(findstring windows, $(1)),.exe).sha256;
endef

.PHONY: cross
cross: VERSION.txt ## Builds the cross-compiled binaries, creating a clean directory structure (eg. GOOS/GOARCH/binary)
	@echo "+ $@"
	$(foreach BINARY,$(BINARIES), $(foreach GOOSARCH,$(GOOSARCHES), $(call buildpretty,$(subst /,,$(dir $(GOOSARCH))),$(notdir $(GOOSARCH)),$(BINARY))))

define buildrelease
GOOS=$(1) GOARCH=$(2) GO111MODULE=on CGO_ENABLED=0 go build \
	 -o $(BUILDDIR)/$(3)-$(1)-$(2)$(if $(findstring windows, $(1)),.exe) \
	 -a -tags "$(BUILDTAGS) static_build netgo" \
	 -installsuffix netgo $(call GO_LDFLAGS_STATIC,$3) $(BASE_BINARIES);
md5sum $(BUILDDIR)/$(3)-$(1)-$(2)$(if $(findstring windows, $(1)),.exe) > $(BUILDDIR)/$(3)-$(1)-$(2)$(if $(findstring windows, $(1)),.exe).md5;
sha256sum $(BUILDDIR)/$(3)-$(1)-$(2)$(if $(findstring windows, $(1)),.exe) > $(BUILDDIR)/$(3)-$(1)-$(2)$(if $(findstring windows, $(1)),.exe).sha256;
endef

.PHONY: release
release: VERSION.txt ## Builds the cross-compiled binaries, naming them in such a way for release (eg. binary-GOOS-GOARCH)
	@echo "+ $@"
	$(foreach BINARY,$(BINARIES), $(foreach GOOSARCH,$(GOOSARCHES), $(call buildrelease,$(subst /,,$(dir $(GOOSARCH))),$(notdir $(GOOSARCH)),$(BINARY))))

.PHONY: bump-version
BUMP := patch
bump-version: ## Bump the version in the version file. Set BUMP to [ patch | major | minor ]
	$(eval NEW_VERSION = $(shell sembump --kind $(BUMP) $(VERSION)))
	@echo "Bumping VERSION.txt from $(VERSION) to $(NEW_VERSION)"
	echo $(NEW_VERSION) > VERSION.txt
	@echo "Updating links to download binaries in README.md"
	sed -e s/$(VERSION)/$(NEW_VERSION)/g README.md > README.md.tmp
	mv README.md.tmp README.md
	git add VERSION.txt README.md
	git commit -vsm "Bump version to $(NEW_VERSION)"
	@echo "Run make tag to create and push the tag for new version $(NEW_VERSION)"

.PHONY: tag
tag: ## Create a new git tag to prepare to build a release
	git tag -sa $(VERSION) -m "$(VERSION)"
	@echo "Run git push origin $(VERSION) to push your new tag to GitHub and trigger a travis build."

.PHONY: AUTHORS
AUTHORS:
	@$(file >$@,# This file lists all individuals having contributed content to the repository.)
	@$(file >>$@,# For how it is generated, see `make AUTHORS`.)
	@echo "$(shell git log --format='\n%aN <%aE>' | LC_ALL=C.UTF-8 sort -uf)" > $@
	git add AUTHORS
	git commit -vsm "Updated AUTHORS"

.PHONY: clean
clean: ## Cleanup any build binaries or packages
	@echo "+ $@"
	$(foreach BINARY,$(BINARIES), $(RM) $(BINARY))
	$(RM) -r $(BUILDDIR)

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: dev-dependencies
dev-dependencies: ## Install all dev dependencies
	@GO111MODULE=off go get -u github.com/jessfraz/junk/sembump
	@GO111MODULE=off go get -u honnef.co/go/tools/cmd/staticcheck
	@GO111MODULE=off go get -u golang.org/x/lint/golint
