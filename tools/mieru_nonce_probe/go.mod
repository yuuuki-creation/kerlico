module example.invalid/mieru-nonce-probe

go 1.26.0

require github.com/enfein/mieru/v3 v3.38.1

require (
	golang.org/x/crypto v0.33.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
)

replace github.com/enfein/mieru/v3 => ../mieru
