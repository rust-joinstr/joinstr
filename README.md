# Sponsorship

[R&D Sponsored By Bull Bitcoin](https://www.bullbitcoin.com/)

# Joinstr protocol
 - [Joinstr website](https://joinstr.xyz/)
 - [Python implementation](https://gitlab.com/invincible-privacy/joinstr)

# Project organisation:

The rust library can be found [here](./rust/joinstr).

The Dart/Flutter bindings can be found [here](./dart), published as the
`joinstr_flutter` package. They wrap the blocking `joinstr::interface` API
through flutter_rust_bridge, and ship a minimal Android example app.

The generated bridge code under `dart/lib/src/generated` is committed so the
package builds as checked out. After changing anything under `dart/rust/src/api`,
run `make -C dart generate-bindings` and commit the result; CI fails if the
committed output is stale.



