VERSION := $(shell echo $(shell git describe --tags --always) | sed 's/^v//')

export GO111MODULE = on

build: go.sum
	go build -mod=readonly ./...

test: build
	go test -v ./...

install-gomobile:
	go install golang.org/x/mobile/cmd/gomobile@latest
	gomobile init

# With aries-framework-go@v0.1.8 that uses github.com/google/tink/go@v1.6.0,
# this 'build-android' doesn't work with an error: `maxAESGCMPlaintextSize (untyped int constant 68719476704) overflows int`.
# This has been fixed in github.com/google/tink/go@v1.7.0 (https://github.com/google/tink/commit/edf362ffb58af4b057bcdeb409061f2a8f772db6),
#
# So, commenting this command until aries-framework-go adopts github.com/google/tink/go@v1.7.0.
#
#build-android: build install-gomobile
#	gomobile bind -target=android -javapkg=org.medibloc.vc_sdk -o vc-${VERSION}.aar ./...

build-ios: build install-gomobile
	gomobile bind -target=ios -o Vc_${VERSION}.xcframework ./...

clean:
	gomobile clean
	rm -rf *.jar *.aar *.framework
	go clean
