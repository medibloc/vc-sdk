# vc-sdk
Verifiable Credential/Presentation SDK written in Go (+ mobile bindings)


## Features

- Signing Credentials
- Verifying Credentials
- Signing Presentations
- Verifying Presentations


## Building and Testing

```bash
go build ./...

go test ./...

# For Android binding (Java)
gomobile bind -target=android ./...

# For iOS binding (Objective-C)
gomobile bind -target=ios ./...
```

## Examples

TBD
