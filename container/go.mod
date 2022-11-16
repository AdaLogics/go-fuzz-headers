module github.com/AdaLogics/go-fuzz-headers/container

go 1.18

require (
	github.com/AdaLogics/go-fuzz-headers v0.0.0-20221103172237-443f56ff4ba8
	github.com/google/go-containerregistry v0.7.0
)

// When developing, use the local code of go-fuzz-headers from main. Be aware
// that replace rules are not transitive; "the rest of the world" will use the
// version that's specified above if go-fuzz-headers is only present as an
// indirect dependency through this module.
//
// As this module would unlikely be used on its own (without "go-fuzz-headers"
// itself as a direct dependency), chances are low that users depend on the
// version specified above, but ideally CI should test both with (latest version
// from main) and without (version specified in go.mod) this replace rule to
// verify that the specified version is compatible.
//
// See https://github.com/moby/sys/pull/68 for a similar scenario.
//
// TODO(thaJeztah): when setting up CI, test both with and without this replace rule.
replace github.com/AdaLogics/go-fuzz-headers => ../

require (
	github.com/containerd/stargz-snapshotter/estargz v0.10.1 // indirect
	github.com/cyphar/filepath-securejoin v0.2.3 // indirect
	github.com/klauspost/compress v1.13.6 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.2-0.20210819154149-5ad6f50d6283 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/vbatts/tar-split v0.11.2 // indirect
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c // indirect
)
