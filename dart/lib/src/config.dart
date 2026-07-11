// ignore_for_file: invalid_use_of_internal_member
import 'dart:io' show Platform;

import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart'
    show ExternalLibrary;

import 'generated/frb_generated.dart';

/// Initializes the joinstr Rust runtime. Call once before any other call.
class JoinstrFlutter {
  static Future<void>? _initFuture;

  static Future<void> init() async {
    if (joinstr.instance.initialized) return;
    // iOS and macOS force-load the Rust static lib into the app binary, so its
    // symbols live in the process rather than a dylib the default loader opens.
    final library = (Platform.isIOS || Platform.isMacOS)
        ? ExternalLibrary.process(iKnowHowToUseIt: true)
        : null;
    final pending = _initFuture ??= joinstr.init(externalLibrary: library);
    try {
      await pending;
    } catch (_) {
      // A transient native-library load failure must not poison every later
      // call: drop the rejected future so the next `init()` retries. Guarded so
      // a concurrent caller that already replaced it keeps its own future.
      if (identical(_initFuture, pending)) _initFuture = null;
      rethrow;
    }
  }
}
