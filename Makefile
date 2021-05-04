VERSION := $(shell echo $(shell git describe --tags --always) | sed 's/^v//')

export GO111MODULE = on

build: go.sum
	go build -mod=readonly ./...

test: build
	go test -v ./...

install-gomobile:
	go get golang.org/x/mobile/cmd/gomobile
	gomobile init

build-android: build install-gomobile
	gomobile bind -target=android -javapkg=org.medibloc.vc_sdk -o vc-${VERSION}.aar ./...

build-ios: build install-gomobile
	CGO_LDFLAGS_ALLOW='-fembed-bitcode' gomobile bind -target=ios -o Vc-${VERSION}.framework ./...

clean:
	gomobile clean
	rm -rf *.jar *.aar *.framework
	go clean
