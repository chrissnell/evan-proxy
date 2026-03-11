APP      := evan-proxy
IMAGE    := ghcr.io/chrissnell/evan-proxy
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
PLATFORM ?= linux/amd64

.PHONY: build test clean docker docker-push deploy helm bump-minor bump-patch

# Get latest semver tag components
LATEST_TAG := $(shell git tag --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$$' | head -1)
TAG_MAJOR  := $(shell echo $(LATEST_TAG) | sed 's/v//' | cut -d. -f1)
TAG_MINOR  := $(shell echo $(LATEST_TAG) | sed 's/v//' | cut -d. -f2)
TAG_PATCH  := $(shell echo $(LATEST_TAG) | sed 's/v//' | cut -d. -f3)

bump-minor:
	$(eval NEW_TAG := v$(TAG_MAJOR).$(shell echo $$(($(TAG_MINOR)+1))).0)
	@echo "$(LATEST_TAG) -> $(NEW_TAG)"
	git tag $(NEW_TAG)
	git push origin main --tags

bump-patch:
	$(eval NEW_TAG := v$(TAG_MAJOR).$(TAG_MINOR).$(shell echo $$(($(TAG_PATCH)+1))))
	@echo "$(LATEST_TAG) -> $(NEW_TAG)"
	git tag $(NEW_TAG)
	git push origin main --tags

build:
	CGO_ENABLED=0 go build -ldflags="-s -w -X main.Version=$(VERSION)" -o $(APP) ./cmd/evan-proxy

test:
	go test ./...

clean:
	rm -f $(APP)

docker:
	docker buildx build --platform $(PLATFORM) --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) .

docker-push:
	docker buildx build --platform $(PLATFORM) --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) --push .

helm:
	helm upgrade evan-proxy helm/evan-proxy -n evan-proxy -f ~/kube/apps/evan-proxy/values.yaml

deploy: docker-push
	helm upgrade evan-proxy helm/evan-proxy -n evan-proxy -f ~/kube/apps/evan-proxy/values.yaml --set image.tag=$(VERSION)
