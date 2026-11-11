// TBFDesk: "Import setup string or device key" (FLUTTER-PORT A3). Port of
// open_import_device_key_dialog / nemoLoadSetupFileInto in src/ui/index.tis.
//
// One field for both kinds of input: a `tbfdesk-setup-v1:` setup string (server values +
// device key, applied all-or-nothing by Rust) or a bare device key. The stored secret is
// never read back; only the public-half fingerprint of the current key is shown. The
// field is not masked so a long setup string can be pasted; "Load from file" avoids
// showing it at all.

import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/models/ab_model.dart';
import 'package:flutter_hbb/models/platform_model.dart';
import 'package:get/get.dart';

/// Bumped after every successful import so the gates re-evaluate at once instead of on
/// their next 3 s tick.
final RxInt nemoGateRefresh = 0.obs;

const int _kMaxSetupFileBytes = 64 * 1024;

Future<String?> _pickSetupFile() async {
  final result = await FilePicker.platform.pickFiles(
    dialogTitle: translate('Import setup string or device key'),
    // TBFDesk: phones reject unknown extensions (tbfsetup) in the picker filter.
    type: (isAndroid || isIOS) ? FileType.any : FileType.custom,
    allowedExtensions:
        (isAndroid || isIOS) ? null : ['tbfsetup', 'txt', 'json'],
  );
  final path = result?.files.single.path;
  if (path == null) return null;
  try {
    final f = File(path);
    // A wrong pick in a file dialog must not pull a huge file into memory.
    if (await f.length() > _kMaxSetupFileBytes) return '';
    return (await f.readAsString()).trim();
  } catch (e) {
    debugPrint('nemo import: cannot read $path: $e');
    return '';
  } finally {
    // TBFDesk: on Android/iOS the picker hands over a COPY in the app cache
    // (cache/file_picker/...). A setup string carries the device's private key, so the
    // copy must not stay behind once it has been read.
    if (isAndroid || isIOS) {
      try {
        await FilePicker.platform.clearTemporaryFiles();
      } catch (_) {}
    }
  }
}

Future<void> showNemoImportDialog(BuildContext context) async {
  final configured = bind.mainNemoDeviceKeyPresent();
  final fingerprint = bind.mainNemoDeviceKeyFingerprint();
  final controller = TextEditingController();
  var error = '';
  var inProgress = false;
  String? summary;

  await gFFI.dialogManager.show((setState, close, context) {
    Future<void> submit() async {
      // Empty means "keep the current key", never "remove": Layer 1 is mandatory and an
      // empty submit must not lock this machine out of the fleet.
      final entered = controller.text.trim();
      setState(() {
        error = '';
        inProgress = true;
      });
      if (entered.isNotEmpty && bind.mainNemoIsSetupString(text: entered)) {
        final err = await bind.mainNemoApplySetupString(text: entered);
        if (err.isNotEmpty) {
          setState(() {
            error = err;
            inProgress = false;
          });
          return;
        }
        summary = await bind.mainNemoSetupSummary();
      } else if (entered.isNotEmpty &&
          !bind.mainNemoDeviceKeyCandidateValid(candidate: entered)) {
        setState(() {
          error = translate(
              'That is not a valid device key or setup string. Check you copied the whole thing with nothing else attached.');
          inProgress = false;
        });
        return;
      } else if (entered.isNotEmpty) {
        await bind.mainSetOption(key: 'nemo-device-key', value: entered);
      }
      close();
      nemoGateRefresh.value++;
    }

    return CustomAlertDialog(
      title: Text(translate('Import setup string or device key')),
      content: ConstrainedBox(
        constraints: const BoxConstraints(minWidth: 420, maxWidth: 520),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            if (configured)
              Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text('${translate('Current device key')}: ',
                        style: const TextStyle(color: Colors.grey)),
                    Expanded(
                      child: SelectableText(fingerprint,
                          style: const TextStyle(fontFamily: 'monospace')),
                    ),
                  ],
                ),
              ),
            Text('${translate('Setup string or device key')}:'),
            const SizedBox(height: 4),
            TextField(
              controller: controller,
              autofocus: true,
              autocorrect: false,
              enableSuggestions: false,
              maxLines: 3,
              minLines: 1,
              decoration: InputDecoration(
                border: const OutlineInputBorder(),
                isDense: true,
                errorText: error.isEmpty ? null : error,
                errorMaxLines: 4,
              ),
              onSubmitted: (_) => submit(),
            ).workaroundFreezeLinuxMint(),
            const SizedBox(height: 6),
            OutlinedButton(
              onPressed: inProgress
                  ? null
                  : () async {
                      final text = await _pickSetupFile();
                      if (text == null) return;
                      if (text.isEmpty) {
                        setState(() => error = translate(
                            'That file could not be read, or it is empty.'));
                        return;
                      }
                      setState(() {
                        controller.text = text;
                        error = '';
                      });
                    },
              child: Text('${translate('Load from file')}...'),
            ),
            const SizedBox(height: 8),
            Text(
              translate(
                  'Paste the device key or the setup string from your TBFDesk server. A setup string also configures the server addresses, so nothing else has to be typed in here.'),
              style: const TextStyle(fontSize: 12, color: Colors.grey),
            ),
            if (configured)
              Padding(
                padding: const EdgeInsets.only(top: 4),
                child: Text(
                  translate(
                      'A device key is already configured. Paste a new one to replace it; leave empty to keep the current key.'),
                  style: const TextStyle(fontSize: 12, color: Colors.grey),
                ),
              ),
            if (inProgress)
              const Padding(
                padding: EdgeInsets.only(top: 8),
                child: LinearProgressIndicator(),
              ),
          ],
        ),
      ),
      actions: [
        dialogButton('Cancel', onPressed: close, isOutline: true),
        dialogButton('OK', onPressed: inProgress ? null : submit),
      ],
      onSubmit: submit,
      onCancel: close,
    );
  });

  // Say what a setup string actually changed: provisioning that succeeds silently is
  // unsupportable over the phone.
  if (summary != null) {
    final lines = summary!.trim();
    await gFFI.dialogManager.show((setState, close, context) {
      return CustomAlertDialog(
        title: Text(translate('Import setup string or device key')),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(translate('Settings imported'),
                style: const TextStyle(fontWeight: FontWeight.bold)),
            const SizedBox(height: 4),
            lines.isEmpty
                ? Text(
                    translate('This client was already configured this way.'),
                    style: const TextStyle(color: Colors.grey))
                : SelectableText(lines),
          ],
        ),
        actions: [dialogButton('OK', onPressed: close)],
        onSubmit: close,
        onCancel: close,
      );
    });
    // The address book comes from the api-server the bundle just configured.
    if (gFFI.userModel.isLogin) {
      gFFI.abModel.pullAb(force: ForcePullAb.listAndCurrent, quiet: false);
    }
  }
}
