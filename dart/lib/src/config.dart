import 'generated/frb_generated.dart';

/// Initializes the joinstr Rust runtime. Call once before any other call.
class JoinstrFlutter {
  static Future<void>? _initFuture;

  static Future<void> init() async {
    if (joinstr.instance.initialized) return;
    final pending = _initFuture ??= joinstr.init();
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
