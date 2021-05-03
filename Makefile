VERSION := $(shell echo $(shell git describe --tags) | sed 's/^v//') || "none"

export GO111MODULE = on

build: go.sum
	go build -mod=readonly ./...

test: build
	go test -v ./...

build-android: build
	gomobile bind -target=android -javapkg=org.medibloc.vc_sdk -o vc-${VERSION}.aar ./...

build-ios: build
	gomobile bind -target=ios -o Vc-${VERSION}.framework ./...

clean:
	gomobile clean
	rm -rf *.jar *.aar *.framework
	go clean
