import 'package:flutter/material.dart';
import 'package:joinstr_flutter/joinstr_flutter.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await JoinstrFlutter.init();
  runApp(const ExampleApp());
}

class ExampleApp extends StatefulWidget {
  const ExampleApp({super.key});

  @override
  State<ExampleApp> createState() => _ExampleAppState();
}

class _ExampleAppState extends State<ExampleApp> {
  static const _relay = 'wss://nos.lol';
  List<FfiPool> _pools = [];
  String? _error;

  Future<void> _refresh() async {
    try {
      final pools = await listPools(
        back: BigInt.from(86400),
        timeout: BigInt.from(5000000),
        relay: _relay,
      );
      if (!mounted) return;
      setState(() {
        _pools = pools;
        _error = null;
      });
    } on JoinstrError catch (e) {
      if (!mounted) return;
      setState(() => _error = e.message);
    }
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(title: const Text('joinstr pools')),
        floatingActionButton: FloatingActionButton(
          onPressed: _refresh,
          child: const Icon(Icons.refresh),
        ),
        body: _error != null
            ? Center(child: Text('Error: $_error'))
            : ListView(
                children: [
                  for (final p in _pools)
                    ListTile(
                      title: Text('${p.denominationSat} sat · ${p.peers} peers'),
                      subtitle: Text(p.id),
                    ),
                ],
              ),
      ),
    );
  }
}
