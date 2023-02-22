module github.com/medibloc/vc-sdk

go 1.16

require (
	github.com/btcsuite/btcd v0.22.2
	github.com/gogo/protobuf v1.3.3
	github.com/hyperledger/aries-framework-go v0.1.6
	github.com/medibloc/panacea-core/v2 v2.0.5
	github.com/piprate/json-gold v0.5.0
	github.com/stretchr/testify v1.8.1
)

replace github.com/hyperledger/aries-framework-go => github.com/medibloc/aries-framework-go v0.1.6

replace (
	github.com/cosmos/cosmos-sdk => github.com/medibloc/cosmos-sdk v0.45.12-panacea.1
	github.com/gogo/protobuf => github.com/regen-network/protobuf v1.3.3-alpha.regen.1
	github.com/tendermint/tendermint => github.com/informalsystems/tendermint v0.34.24
	google.golang.org/grpc => google.golang.org/grpc v1.33.2
)
