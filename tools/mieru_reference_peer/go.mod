module example.invalid/mieru-reference

go 1.26.0

require (
	github.com/enfein/mieru/v3 v3.38.1
	google.golang.org/protobuf v1.34.2
)

require (
	github.com/google/btree v1.1.3 // indirect
	golang.org/x/crypto v0.33.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
)

replace github.com/enfein/mieru/v3 => ../mieru
