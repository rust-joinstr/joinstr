/// Dart/Flutter bindings for the joinstr coinjoin library.
///
/// The Rust-facing API (`listCoins`, `listPools`, `initiateCoinjoin`,
/// `joinCoinjoin`) and the data types live under `src/generated`. That output is
/// committed, so the package builds as checked out; regenerate it with
/// `make generate-bindings` after changing anything under `rust/src/api`.
///
/// Call [JoinstrFlutter.init] once before any other call.
library;

export 'src/config.dart' show JoinstrFlutter;
export 'src/generated/api/joinstr.dart';
export 'src/generated/api/types.dart';
export 'src/generated/api/error.dart';
