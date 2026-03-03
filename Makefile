APP      := evan-proxy
IMAGE    := ghcr.io/chrissnell/evan-proxy
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
PLATFORM ?= linux/amd64

.PHONY: build test clean docker docker-push deploy helm

build:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o $(APP) ./cmd/evan-proxy

test:
	go test ./...

clean:
	rm -f $(APP)

docker:
	docker buildx build --platform $(PLATFORM) -t $(IMAGE):$(VERSION) .

docker-push:
	docker buildx build --platform $(PLATFORM) -t $(IMAGE):$(VERSION) --push .

helm:
	helm upgrade evan-proxy helm/evan-proxy -n evan-proxy -f ~/kube/apps/evan-proxy/values.yaml

deploy: docker-push
	helm upgrade evan-proxy helm/evan-proxy -n evan-proxy -f ~/kube/apps/evan-proxy/values.yaml --set image.tag=$(VERSION)
