module github.com/katzenpost/hpqc

go 1.26.2

require (
	codeberg.org/vula/highctidh v1.0.2025051200
	filippo.io/edwards25519 v1.2.0
	filippo.io/mlkem768 v0.0.0-20260214141301-2e7bebc7d88d
	github.com/agl/gcmsiv v0.0.0-20190418185415-e8dcd2f151dc
	github.com/fxamacker/cbor/v2 v2.9.1
	github.com/go-faster/xor v1.0.0
	github.com/katzenpost/chacha20 v0.0.1
	github.com/katzenpost/chacha20poly1305 v0.0.1
	github.com/katzenpost/circl v1.3.8-0.20260413165442-e2d217fd59f5
	github.com/katzenpost/sntrup4591761 v0.0.0-20231024131303-8755eb1986b8
	github.com/katzenpost/sphincsplus v0.0.2
	github.com/stretchr/testify v1.8.4
	gitlab.com/elixxir/crypto v0.0.12
	gitlab.com/xx_network/crypto v0.0.6
	golang.org/x/crypto v0.51.0
)

require github.com/katzenpost/falcon v0.1.0

require github.com/shurlinet/go-hqc v0.1.1

require github.com/katzenpost/sqisign/bindings/go v0.0.0-20260520191751-d4ef01ebd052

// The sqisign Go binding's cgo directive statically links the
// sqisign-ffi staticlib by a path relative to the binding's source
// directory: ${SRCDIR}/../../../target/release/libsqisign_ffi.a. That
// path only resolves when the source tree is on disk; when Go caches
// the module under pkg/mod the surrounding target/ directory is not
// present and the link fails. We therefore replace the module with
// the local sqisign checkout, assuming the conventional layout where
// hpqc/ and sqisign/ are siblings in the same parent directory.
//
// The proper fix is for the sqisign binding to source its LDFLAGS
// from an environment variable (or pkg-config); until then this
// replace is the simplest way to make hpqc actually build.
replace github.com/katzenpost/sqisign/bindings/go => ../sqisign/bindings/go

require (
	filippo.io/mldsa v0.0.0-20260215214346-43d0283efc3e
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/mattn/go-pointer v0.0.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/sys v0.44.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
