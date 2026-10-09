NAME=gocurl
BASE_BUILDDIR=build
BUILDNAME=$(GOOS)-$(GOARCH)
BUILDDIR=$(BASE_BUILDDIR)/$(BUILDNAME)
VERSION?=v0.0-dev
VERSIONPKG=github.com/ameshkov/gocurl/internal/appversion

ifeq ($(GOOS),windows)
  ext=.exe
  archiveCmd=zip -9 -r $(NAME)-$(BUILDNAME)-$(VERSION).zip $(BUILDNAME)
else
  ext=
  archiveCmd=tar czpvf $(NAME)-$(BUILDNAME)-$(VERSION).tar.gz $(BUILDNAME)
endif

.PHONY: default build-check check init lint test verify vet
default: build

build: clean
	CGO_ENABLED=0 go build -mod=vendor -ldflags "-X $(VERSIONPKG).version=$(VERSION)" -o $(NAME)

release: check-env-release
	mkdir -p $(BUILDDIR)
	cp LICENSE $(BUILDDIR)/
	cp README.md $(BUILDDIR)/
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -mod=vendor -ldflags "-X $(VERSIONPKG).version=$(VERSION)" -o $(BUILDDIR)/$(NAME)$(ext)
	cd $(BASE_BUILDDIR) ; $(archiveCmd)

lint:
	npx markdownlint-cli .
	golangci-lint run --modules-download-mode=vendor

test:
	go test -race -count=1 -v -bench=. -mod=vendor ./...
	go test -race -count=1 -v -mod=vendor -run 'Test(ReorderTransportParametersKeepsGreaseAndUnlistedOrder|TransportParametersMarshalUsesConfiguredOrder|TransportParametersMarshalPreservesExplicitZeroValues)$$' github.com/quic-go/quic-go/internal/wire

verify:
	go mod verify

vet:
	go vet -mod=vendor ./...

build-check:
	go build -mod=vendor ./...

# check runs linters and tests, it mirrors the CI quality gate.
check: verify lint vet test build-check

# init installs the git pre-commit hook, see .githooks/pre-commit.
init:
	@ echo "Installing the gocurl pre-commit hook..."
	@ mkdir -p .git/hooks
	@ cp .githooks/pre-commit .git/hooks/pre-commit
	@ chmod +x .git/hooks/pre-commit
	@ echo "Done. The pre-commit hook is installed at .git/hooks/pre-commit."
	@ echo "It runs on every commit: checks for temporary TODOs, linters, tests."

clean:
	go clean
	rm -rf $(BASE_BUILDDIR)

check-env-release:
	@ if [ "$(GOOS)" = "" ]; then \
		echo "Environment variable GOOS not set"; \
		exit 1; \
	fi
	@ if [ "$(GOARCH)" = "" ]; then \
		echo "Environment variable GOARCH not set"; \
		exit 1; \
	fi
