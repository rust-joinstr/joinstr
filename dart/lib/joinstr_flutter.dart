/// Dart/Flutter bindings for the joinstr coinjoin library.
///
/// The Rust-facing API (`listCoins`, `listPools`, `initiateCoinjoin`,
/// `joinCoinjoin`) and the data types live under `src/generated`, produced by
/// `flutter_rust_bridge_codegen generate`. Run codegen before using the package.
library;

export 'src/config.dart' show JoinstrFlutter;
export 'src/generated/api/joinstr.dart';
export 'src/generated/api/types.dart';
export 'src/generated/api/error.dart';
