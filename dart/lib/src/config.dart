import 'generated/frb_generated.dart';

/// Initializes the joinstr Rust runtime. Call once before any other call.
class JoinstrFlutter {
  static Future<void>? _initFuture;

  static Future<void> init() async {
    if (joinstr.instance.initialized) return;
    _initFuture ??= joinstr.init();
    await _initFuture;
  }
}
