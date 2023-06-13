module mnemonic

go 1.12

require (
	github.com/btcsuite/btcd v0.20.1-beta
	github.com/btcsuite/btcutil v1.0.1
	github.com/ethereum/go-ethereum v1.9.11
	github.com/pborman/uuid v0.0.0-20170112150404-1b00554d8222
	github.com/tyler-smith/go-bip39 v1.0.2
	golang.org/x/sys v0.0.0-20211020174200-9d6173849985 // indirect
)

//replace github.com/btcsuite/btcd/chaincfg/chainhash => github.com/btcsuite/btcd v0.20.1-beta
