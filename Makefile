# Image coordinates. Tag defaults to the current git description.
REGISTRY ?= ghcr.io/trickyearlobe
IMAGE    ?= opnsense-operator
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
IMG      ?= $(REGISTRY)/$(IMAGE):$(VERSION)
CHART    := charts/opnsense-operator

# Stamp the version into the binary.
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: help
help: ## List targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

## --- build / test ---------------------------------------------------------

.PHONY: build
build: ## Compile the manager binary
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/manager ./cmd/manager

.PHONY: test
test: ## Run unit tests
	go test -race -count=1 ./...

.PHONY: vet
vet: ## go vet
	go vet ./...

.PHONY: fmt
fmt: ## Format sources
	gofmt -w .

.PHONY: fmt-check
fmt-check: ## Fail if any file is unformatted
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "unformatted:"; echo "$$out"; exit 1; fi

.PHONY: tidy
tidy: ## go mod tidy
	go mod tidy

.PHONY: run
run: ## Run locally against your current kubecontext (needs OPNSENSE_* env)
	go run ./cmd/manager

## --- security / supply chain (run the same tools CI runs) -----------------

.PHONY: lint
lint: ## golangci-lint (install: https://golangci-lint.run)
	golangci-lint run ./...

.PHONY: vuln
vuln: ## govulncheck — known vulnerable symbols in deps
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

.PHONY: sec
sec: ## gosec SAST
	go run github.com/securego/gosec/v2/cmd/gosec@latest -exclude-generated ./...

.PHONY: scan
scan: ## Trivy filesystem scan (vulns + misconfig + secrets)
	trivy fs --scanners vuln,misconfig,secret --severity HIGH,CRITICAL .

## --- image / chart --------------------------------------------------------

.PHONY: docker-build
docker-build: ## Build the container image
	docker build -t $(IMG) .

.PHONY: helm-lint
helm-lint: ## Lint the Helm chart
	helm lint $(CHART)

.PHONY: helm-template
helm-template: ## Render the chart with sample values
	helm template op $(CHART) --set opnsense.apiKey=KEY --set opnsense.apiSecret=SECRET

.PHONY: helm-package
helm-package: ## Package the chart (version/appVersion from VERSION, sans leading v)
	helm package $(CHART) --version $(VERSION:v%=%) --app-version $(VERSION:v%=%) -d dist/

## --- install (Helm) -------------------------------------------------------

.PHONY: deploy
deploy: ## Install/upgrade via Helm (pass OPNSENSE creds with --set or values)
	helm upgrade --install opnsense-operator $(CHART) \
	  --namespace opnsense-system --create-namespace

.PHONY: undeploy
undeploy: ## Uninstall the Helm release
	helm uninstall opnsense-operator --namespace opnsense-system

## --- release: bump a semver tag and push (triggers the release workflow) ---

.PHONY: bump-patch-push bump-minor-push bump-major-push
bump-patch-push: ## Tag next patch (vX.Y.Z+1) and push
	./hack/bump-version.sh patch
bump-minor-push: ## Tag next minor (vX.Y+1.0) and push
	./hack/bump-version.sh minor
bump-major-push: ## Tag next major (vX+1.0.0) and push
	./hack/bump-version.sh major
