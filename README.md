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
committed output is stale. Codegen formats `frb_generated.rs` with `rustfmt`, so
run it with `rustfmt` installed or the output will differ from what CI produces.

## Android: Gradle 8.x only

Apps consuming `joinstr_flutter` must build with Gradle 8.x. The vendored
cargokit (`dart/cargokit/gradle/plugin.gradle`) calls `project.exec {}`, which
Gradle 9 removed, so a Gradle 9 build fails inside the cargokit task with an
opaque `Could not find method exec()`. The bundled example pins Gradle 8.13 and
AGP 8.12.2.



