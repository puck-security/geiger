// Package modules is the credential catalog. Each file registers one or more
// modules (recipe-built or hand-written), their gitleaks rule mappings, and any
// custom set/file recognizers, via init(). Importing this package for its side
// effects populates module.Default.
package modules
