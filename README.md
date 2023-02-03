# vc-sdk
Verifiable Credential/Presentation SDK written in Go (+ mobile bindings)


## Features

- Signing Credentials
- Verifying Credentials
- Signing Presentations
- Verifying Presentations

## Usage


```go

frameWork := vc.NewFramework()

framework.SignCredential(...)
framework.VerifyCredential(...)
framework.SignPresentation(...)
framework.VerifyPresentation(...)
```


## Building and Testing

```bash
make build
make test

make build-android
make build-ios
```

## Examples

TBD
