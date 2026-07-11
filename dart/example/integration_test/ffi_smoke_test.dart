// Runtime smoke tests for the FFI boundary.
//
// A build-only CI job proves the native library links; these prove it is
// callable: that `JoinstrFlutter.init()` loads the library on the target
// platform and that a call marshals its arguments into Rust and returns a
// typed `JoinstrError` rather than crashing the isolate.
//
// Every assertion here is deterministic and offline. `interface::list_coins`
// runs `check_scan_range` before it constructs a signer or opens an electrum
// connection, so these never touch the network and cannot flake on a relay or
// electrum server being unreachable.
//
// Run on a booted device or simulator:
//   cd dart/example && flutter test integration_test/ffi_smoke_test.dart

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:joinstr_flutter/joinstr_flutter.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  setUpAll(() async {
    // Loads libjoinstr_flutter and starts the Rust runtime. If the platform's
    // artifact failed to link the four wire symbols, this throws before any
    // test body runs.
    await JoinstrFlutter.init();
  });

  group('FFI boundary is live', () {
    test('init is idempotent', () async {
      // The second call must be a no-op, not a re-init or a hang.
      await JoinstrFlutter.init();
    });

    test('inverted scan range surfaces a typed JoinstrError', () async {
      // `check_scan_range` rejects end < start before any signer/electrum work,
      // so this is a pure offline round trip across the boundary.
      await expectLater(
        listCoins(
          mnemonic: 'x',
          electrumAddress: '127.0.0.1',
          electrumPort: 50001,
          rangeStart: 10,
          rangeEnd: 5,
          network: BitcoinNetwork.regtest,
        ),
        throwsA(
          isA<JoinstrError>().having(
            (e) => e.message,
            'message',
            contains('invalid range'),
          ),
        ),
      );
    });

    test('oversized scan span surfaces a typed JoinstrError', () async {
      // MAX_SCAN_SPAN is 100_000; a wider span is rejected by the same guard.
      await expectLater(
        listCoins(
          mnemonic: 'x',
          electrumAddress: '127.0.0.1',
          electrumPort: 50001,
          rangeStart: 0,
          rangeEnd: 200000,
          network: BitcoinNetwork.regtest,
        ),
        throwsA(
          isA<JoinstrError>().having(
            (e) => e.message,
            'message',
            contains('exceeds maximum'),
          ),
        ),
      );
    });

    test('invalid mnemonic surfaces a typed JoinstrError', () async {
      // A valid range clears the guard, so this exercises a different Rust
      // origin: the signer rejects the mnemonic during construction, before any
      // electrum connection. The message text is owned by the signer layer, so
      // assert only that the failure crosses the boundary as JoinstrError with
      // a non-empty message rather than pinning a brittle string.
      await expectLater(
        listCoins(
          mnemonic: 'not a valid bip39 mnemonic',
          electrumAddress: '127.0.0.1',
          electrumPort: 50001,
          rangeStart: 0,
          rangeEnd: 1,
          network: BitcoinNetwork.regtest,
        ),
        throwsA(
          isA<JoinstrError>().having(
            (e) => e.message,
            'message',
            isNotEmpty,
          ),
        ),
      );
    });
  });
}
