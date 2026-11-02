// TBFDesk: the update prompt the service shows in the user's session before it installs
// an update (updater::prompt_user spawns `<exe> --nemo-update-prompt <version>
// <postpone 1|0> <seconds>`). Port of src/ui/update.html.
//
// Silence is consent: when the countdown ends the window closes WITHOUT an answer and
// the service installs. "Postpone" (only if the policy allows it) and "Now" send the
// decision through main_nemo_update_answer (updater::OPTION_UPDATE_DECISION).

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/models/platform_model.dart';
import 'package:window_manager/window_manager.dart';

class NemoUpdatePromptArgs {
  final String version;
  final bool postpone;
  final int seconds;

  const NemoUpdatePromptArgs(
      {required this.version, required this.postpone, required this.seconds});

  /// `args` as the process received them: `--nemo-update-prompt <version> <1|0> <secs>`.
  factory NemoUpdatePromptArgs.parse(List<String> args) {
    final i = args.indexOf('--nemo-update-prompt');
    String at(int k) => (i >= 0 && i + k < args.length) ? args[i + k] : '';
    final secs = int.tryParse(at(3)) ?? 60;
    return NemoUpdatePromptArgs(
      version: at(1),
      postpone: at(2) == '1',
      seconds: secs > 0 ? secs : 60,
    );
  }
}

class NemoUpdatePrompt extends StatefulWidget {
  final NemoUpdatePromptArgs args;

  const NemoUpdatePrompt({Key? key, required this.args}) : super(key: key);

  @override
  State<NemoUpdatePrompt> createState() => _NemoUpdatePromptState();
}

class _NemoUpdatePromptState extends State<NemoUpdatePrompt> {
  late int _left;
  Timer? _timer;
  bool _answered = false;

  @override
  void initState() {
    super.initState();
    _left = widget.args.seconds;
    _timer = Timer.periodic(const Duration(seconds: 1), (t) {
      if (!mounted) return;
      setState(() => _left -= 1);
      if (_left <= 0) {
        t.cancel();
        _close();
      }
    });
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  Future<void> _close() async {
    await windowManager.setPreventClose(false);
    await windowManager.close();
  }

  Future<void> _answer(String choice) async {
    if (_answered) return;
    _answered = true;
    _timer?.cancel();
    await bind.mainNemoUpdateAnswer(
        choice: choice, version: widget.args.version);
    await _close();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Scaffold(
      body: Padding(
        padding: const EdgeInsets.fromLTRB(24, 22, 24, 18),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(translate('nemo_update_prompt_title'),
                style: theme.textTheme.titleLarge
                    ?.copyWith(fontWeight: FontWeight.bold)),
            const SizedBox(height: 10),
            Text(
              translate('nemo_update_prompt_text')
                  .replaceAll('{}', widget.args.version),
              style: const TextStyle(height: 1.5),
            ),
            const SizedBox(height: 12),
            Text(
              translate('nemo_update_countdown')
                  .replaceAll('{}', _left.toString()),
              style: TextStyle(color: theme.hintColor),
            ),
            const Spacer(),
            Row(
              children: [
                const Spacer(),
                if (widget.args.postpone)
                  OutlinedButton(
                    onPressed: () => _answer('postpone'),
                    child: Text(translate('nemo_update_postpone')),
                  ),
                const SizedBox(width: 12),
                ElevatedButton(
                  onPressed: () => _answer('now'),
                  child: Text(translate('nemo_update_now')),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}
