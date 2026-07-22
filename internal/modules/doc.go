// Package modules is the credential catalog. Each file registers one or more
// modules (recipe-built or hand-written), their gitleaks rule mappings, and any
// custom set/file recognizers, via init(). Importing this package for its side
// effects populates module.Default.
//
// # Endpoints come from untrusted input
//
// A recognizer runs over a file an attacker may have written. Any host it reads
// out of that file — a co-located env var, a URL matched in the raw blob, a
// hostname concatenated into a base — is therefore attacker-reachable, and a
// planted value aims a real credential at whoever planted it. When writing a
// module that takes its destination from the blob:
//
//   - Declare an Endpoint policy (module.EndpointPolicy): saasOnly(...) with the
//     vendor's own domains for a SaaS-only service, selfHosted for anything
//     deployable at an arbitrary domain. recognize.Recognize enforces it before
//     any module code runs, which is what protects an Authenticate hook too.
//   - Resolve the host with resolveEndpoint, which puts the operator's
//     --endpoint ahead of anything in the file. Do not hand-roll that ordering:
//     letting the file win means an operator can name a host and still have the
//     credential sent somewhere else.
//   - Bind each host variable to the service it names. Pairing one service's
//     credential with another service's URL variable lets a single planted line
//     redirect an unrelated token.
//
// TestEveryEndpointSteeredModuleDeclaresAPolicy fails the build when a module
// aims its calls with a URL-valued field and declares no policy.
package modules
