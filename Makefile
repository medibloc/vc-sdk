VERSION := $(shell echo $(shell git describe --tags --always) | sed 's/^v//')

export GO111MODULE = on

build: go.sum
	go build -mod=readonly ./...

test: build
	go test -v ./...

install-gomobile:
	go install golang.org/x/mobile/cmd/gomobile@latest
	gomobile init

build-android: build install-gomobile
	gomobile bind -target=android -androidapi=23 -javapkg=org.medibloc.vc_sdk -o vc-${VERSION}.aar ./...

build-ios: build install-gomobile
	gomobile bind -target=ios -o Vc_${VERSION}.xcframework ./...

clean:
	gomobile clean
	rm -rf *.jar *.aar *.framework
	go clean
