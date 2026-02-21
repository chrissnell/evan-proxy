APP      := evan-proxy
IMAGE    := ghcr.io/chrissnell/evan-proxy
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test clean docker docker-push

build:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o $(APP) .

test:
	go test ./...

clean:
	rm -f $(APP)

docker:
	docker build -t $(IMAGE):$(VERSION) -t $(IMAGE):latest .

docker-push: docker
	docker push $(IMAGE):$(VERSION)
	docker push $(IMAGE):latest
