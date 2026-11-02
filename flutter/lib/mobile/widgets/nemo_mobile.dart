// TBFDesk: the phone-only pieces of the TBFDesk port (FLUTTER-PORT §9b, §10 "Mobile").
// Settings rows (Alias, Management, Import with QR, language DE/AT/EN, Share log),
// QR import of a setup string, the registration badge on the share-screen page and
// the Direct / Relay badge of a session. The desktop counterparts live in
// desktop_setting_page.dart, desktop_home_page.dart, connection_page.dart and
// remote_toolbar.dart; these versions use phone layouts (no fixed label widths, no
// hover tooltips, share sheet instead of the clipboard).

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/common/shared_state.dart';
import 'package:flutter_hbb/common/widgets/nemo_import_dialog.dart';
import 'package:flutter_hbb/common/widgets/nemo_lang_flag.dart';
import 'package:flutter_hbb/consts.dart';
import 'package:flutter_hbb/desktop/pages/desktop_setting_page.dart'
    show
        kNemoOptionAlias,
        kNemoOptionManagementEnabled,
        kNemoOptionManagementServer,
        kNemoOptionManagementPublicKey;
import 'package:flutter_hbb/mobile/pages/home_page.dart';
import 'package:flutter_hbb/mobile/pages/scan_page.dart';
import 'package:flutter_hbb/models/ab_model.dart';
import 'package:flutter_hbb/models/platform_model.dart';
import 'package:get/get.dart';
import 'package:path_provider/path_provider.dart';
import 'package:share_plus/share_plus.dart';

const Color _kNemoGreen = Color(0xFF1A7A34);

// ---------------------------------------------------------------------------
// Import: paste / file (shared dialog) or QR scan of a setup string.
// ---------------------------------------------------------------------------

/// "Import setup string or device key" on the phone: choose between the shared
/// paste / file dialog and scanning the setup string's QR code.
Future<void> showNemoMobileImport(BuildContext context) async {
  final choice = await showModalBottomSheet<String>(
    context: context,
    builder: (ctx) => SafeArea(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          ListTile(
            title: Text(translate('Import setup string or device key'),
                style: const TextStyle(fontWeight: FontWeight.bold)),
          ),
          ListTile(
            leading: const Icon(Icons.content_paste),
            title: Text(translate('Paste or load from file')),
            onTap: () => Navigator.of(ctx).pop('paste'),
          ),
          ListTile(
            leading: const Icon(Icons.qr_code_scanner),
            title: Text(translate('Scan QR code')),
            onTap: () => Navigator.of(ctx).pop('scan'),
          ),
        ],
      ),
    ),
  );
  if (!context.mounted) return;
  if (choice == 'paste') {
    await showNemoImportDialog(context);
  } else if (choice == 'scan') {
    await Navigator.push(
        context, MaterialPageRoute(builder: (BuildContext _) => ScanPage()));
  }
}

/// Apply a setup string read from a QR code, exactly like a pasted one in the import
/// dialog: all-or-nothing apply in Rust, then the "Settings imported" summary, the gates
/// re-evaluated and the address book reloaded. true = applied.
Future<bool> nemoApplyScannedSetup(String text) async {
  final setup = text.trim();
  if (!bind.mainNemoIsSetupString(text: setup)) return false;
  final tag = gFFI.dialogManager.showLoading(translate('Waiting'));
  String err;
  String summary = '';
  try {
    err = await bind.mainNemoApplySetupString(text: setup);
    if (err.isEmpty) summary = (await bind.mainNemoSetupSummary()).trim();
  } catch (e) {
    err = '$e';
  } finally {
    gFFI.dialogManager.dismissByTag(tag);
  }
  if (err.isNotEmpty) {
    await gFFI.dialogManager.show((setState, close, context) {
      return CustomAlertDialog(
        title: Text(translate('Import setup string or device key')),
        content: SelectableText(err),
        actions: [dialogButton('OK', onPressed: close)],
        onSubmit: close,
        onCancel: close,
      );
    });
    return false;
  }
  nemoGateRefresh.value++;
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
          summary.isEmpty
              ? Text(translate('This client was already configured this way.'),
                  style: const TextStyle(color: Colors.grey))
              : SelectableText(summary),
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
  return true;
}

// ---------------------------------------------------------------------------
// Share log (Sciter "Copy recent log"; §10 mobile 11).
// ---------------------------------------------------------------------------

/// Collect the redacted recent log and hand it to the system share sheet (mail, Teams,
/// Webex, Telegram, WhatsApp, Signal, ...). Shared as a .txt file: the log can be larger
/// than an Android share intent may carry as plain text.
Future<void> nemoShareRecentLog(BuildContext context) async {
  Rect? origin;
  final box = context.findRenderObject();
  if (box is RenderBox && box.hasSize) {
    // Needed on iPad, where the share sheet is a popover.
    origin = box.localToGlobal(Offset.zero) & box.size;
  }
  Map<String, dynamic> r = {};
  try {
    r = jsonDecode(await bind.mainNemoRecentLog()) as Map<String, dynamic>;
  } catch (e) {
    r = {'error': '$e'};
  }
  final text = r['text'] as String?;
  if (text == null || text.isEmpty) {
    msgBoxCommon(
        gFFI.dialogManager,
        translate('Share log'),
        Text('${translate('nemo_copy_log_failed')} ${r['error'] ?? ''}'),
        [dialogButton('OK', onPressed: () => gFFI.dialogManager.dismissAll())]);
    return;
  }
  var id = '';
  try {
    id = (await bind.mainGetMyId()).replaceAll(RegExp(r'[^A-Za-z0-9_-]'), '');
  } catch (_) {}
  final now = DateTime.now();
  String two(int v) => v.toString().padLeft(2, '0');
  final stamp = '${now.year}${two(now.month)}${two(now.day)}-'
      '${two(now.hour)}${two(now.minute)}${two(now.second)}';
  final subject = id.isEmpty ? 'TBFDesk log' : 'TBFDesk log $id';
  try {
    final dir = await getTemporaryDirectory();
    final file =
        File('${dir.path}/tbfdesk-log${id.isEmpty ? '' : '-$id'}-$stamp.txt');
    await file.writeAsString(text);
    await Share.shareXFiles([XFile(file.path, mimeType: 'text/plain')],
        subject: subject, text: subject, sharePositionOrigin: origin);
  } catch (e) {
    debugPrint('nemo share log as file failed: $e');
    try {
      await Share.share(text, subject: subject, sharePositionOrigin: origin);
    } catch (e2) {
      msgBoxCommon(gFFI.dialogManager, translate('Share log'),
          Text('${translate('nemo_copy_log_failed')} $e2'), [
        dialogButton('OK', onPressed: () => gFFI.dialogManager.dismissAll())
      ]);
    }
  }
}

// ---------------------------------------------------------------------------
// Settings dialogs: Alias, Management, Language.
// ---------------------------------------------------------------------------

/// Alias (option nemo-alias). Read-only, with a note, when the management server
/// pushes it.
void showNemoMobileAliasDialog({VoidCallback? onChanged}) {
  final isFixed = isOptionFixed(kNemoOptionAlias) == true;
  final oldAlias = bind.mainGetOptionSync(key: kNemoOptionAlias);
  final controller = TextEditingController(text: oldAlias);
  gFFI.dialogManager.show((setState, close, context) {
    submit() async {
      if (!isFixed) {
        final alias = controller.text.trim();
        if (alias != oldAlias) {
          await bind.mainSetOption(key: kNemoOptionAlias, value: alias);
          onChanged?.call();
        }
      }
      close();
    }

    return CustomAlertDialog(
      title: Text(translate('Alias')),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
              translate(
                  'Give this computer a friendly name shown instead of its number.'),
              style: const TextStyle(fontSize: 12, color: Colors.grey)),
          TextField(
            controller: controller,
            enabled: !isFixed,
            autofocus: !isFixed,
            decoration: InputDecoration(labelText: translate('Alias')),
          ),
          if (isFixed)
            Opacity(
              opacity: 0.7,
              child: Text(
                  translate('This value is managed by your administrator.')),
            ).marginOnly(top: 6),
        ],
      ),
      actions: [
        if (!isFixed) dialogButton('Cancel', onPressed: close, isOutline: true),
        dialogButton(isFixed ? 'Close' : 'OK', onPressed: submit),
      ],
      onSubmit: submit,
      onCancel: close,
    );
  });
}

/// Management server URL, its public key and whether management control is enabled.
/// Same validation and write order as the desktop / Sciter dialog.
void showNemoMobileManagementDialog({VoidCallback? onChanged}) {
  final oldEnabled =
      bind.mainGetOptionSync(key: kNemoOptionManagementEnabled) == 'Y';
  final oldServer = bind.mainGetOptionSync(key: kNemoOptionManagementServer);
  final oldPublicKey =
      bind.mainGetOptionSync(key: kNemoOptionManagementPublicKey);
  final enabledFixed = isOptionFixed(kNemoOptionManagementEnabled) == true;
  final serverFixed = isOptionFixed(kNemoOptionManagementServer) == true;
  final publicKeyFixed = isOptionFixed(kNemoOptionManagementPublicKey) == true;
  final serverCtrl = TextEditingController(text: oldServer);
  final publicKeyCtrl = TextEditingController(text: oldPublicKey);
  var enabled = oldEnabled;
  var errMsg = '';
  var isInProgress = false;

  gFFI.dialogManager.show((setState, close, context) {
    submit() async {
      final server = serverCtrl.text.trim();
      final publicKey = publicKeyCtrl.text.trim();
      if (enabled && server.isEmpty) {
        setState(() => errMsg = translate('Management Server is required'));
        return;
      }
      if (server.isNotEmpty &&
          !server.startsWith('https://') &&
          !server.startsWith('http://')) {
        setState(() => errMsg =
            '${translate('Management Server')}: ${translate('invalid_http')}');
        return;
      }
      if (enabled == oldEnabled &&
          server == oldServer &&
          publicKey == oldPublicKey) {
        close();
        return;
      }
      setState(() {
        errMsg = '';
        isInProgress = true;
      });
      // Switch management off before touching its address, and on only after the
      // address and key are in place.
      if (!enabled) {
        await bind.mainSetOption(key: kNemoOptionManagementEnabled, value: '');
      }
      await bind.mainSetOption(key: kNemoOptionManagementServer, value: server);
      await bind.mainSetOption(
          key: kNemoOptionManagementPublicKey, value: publicKey);
      if (enabled) {
        await bind.mainSetOption(key: kNemoOptionManagementEnabled, value: 'Y');
      }
      setState(() => isInProgress = false);
      close();
      onChanged?.call();
    }

    return CustomAlertDialog(
      title: Text(translate('Management')),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          TextField(
            controller: serverCtrl,
            enabled: !serverFixed,
            autocorrect: false,
            enableSuggestions: false,
            keyboardType: TextInputType.url,
            decoration: InputDecoration(
                labelText: translate('Management Server'),
                hintText: 'https://'),
          ),
          TextField(
            controller: publicKeyCtrl,
            enabled: !publicKeyFixed,
            autocorrect: false,
            enableSuggestions: false,
            decoration: InputDecoration(labelText: translate('Public Key')),
          ),
          const SizedBox(height: 8),
          CheckboxListTile(
            contentPadding: EdgeInsets.zero,
            controlAffinity: ListTileControlAffinity.leading,
            value: enabled,
            onChanged: enabledFixed
                ? null
                : (v) => setState(() => enabled = v ?? false),
            title: Text(translate('Enable management control')),
          ),
          if (errMsg.isNotEmpty)
            Text(errMsg, style: const TextStyle(color: Colors.red))
                .marginOnly(top: 8),
          if (isInProgress) const LinearProgressIndicator().marginOnly(top: 8),
        ],
      ),
      actions: [
        dialogButton('Cancel', onPressed: close, isOutline: true),
        dialogButton('OK', onPressed: isInProgress ? null : submit),
      ],
      onSubmit: submit,
      onCancel: close,
    );
  });
}

/// The current UI language with its flag, for the settings row.
Widget nemoMobileLangValue() {
  final code = nemoCurrentLang();
  final choice = kNemoLangChoices.firstWhereOrNull((c) => c.code == code);
  return Row(
    mainAxisSize: MainAxisSize.min,
    children: [
      NemoLangFlag(code: code, width: 18),
      const SizedBox(width: 6),
      Text(choice?.label ?? code),
    ],
  );
}

/// Only Deutsch (Deutschland), Deutsch (Österreich) and English, with drawn flags. An
/// unset / "default" option is German (src/lang.rs default).
void showNemoMobileLanguageSettings(OverlayDialogManager dialogManager,
    {VoidCallback? onChanged}) {
  var lang = nemoCurrentLang();
  final isOptFixed = isOptionFixed(kCommConfKeyLang) == true;
  dialogManager.show((setState, close, context) {
    setLang(String? v) async {
      if (v == null || v == lang) return;
      setState(() => lang = v);
      await bind.mainSetLocalOption(key: kCommConfKeyLang, value: v);
      HomePage.homeKey.currentState?.refreshPages();
      onChanged?.call();
      Future.delayed(const Duration(milliseconds: 200), close);
    }

    return CustomAlertDialog(
      content: Column(
        mainAxisSize: MainAxisSize.min,
        children: kNemoLangChoices
            .map((c) => getRadio<String>(
                Row(children: [
                  NemoLangFlag(code: c.code),
                  const SizedBox(width: 10),
                  Expanded(child: Text(c.label)),
                ]),
                c.code,
                lang,
                isOptFixed ? null : setLang))
            .toList(),
      ),
    );
  }, backDismiss: true, clickMaskDismiss: true);
}

// ---------------------------------------------------------------------------
// Registration badge (A15) next to "Ready" on the share-screen page.
// ---------------------------------------------------------------------------

/// "Registered" (green) / "Not registered" / "No device key" (orange), same rules as
/// the desktop status bar. Shown only while the rendezvous server answers AND the
/// status reports `key_confirmed`; a status without that field (the mobile FFI does not
/// send it today) means unknown, and nothing is shown.
class NemoRegistrationBadge extends StatefulWidget {
  const NemoRegistrationBadge({Key? key}) : super(key: key);

  @override
  State<NemoRegistrationBadge> createState() => _NemoRegistrationBadgeState();
}

class _NemoRegistrationBadgeState extends State<NemoRegistrationBadge> {
  Timer? _timer;
  int _status = 0;
  bool? _keyConfirmed;

  @override
  void initState() {
    super.initState();
    _refresh();
    _timer = Timer.periodic(const Duration(seconds: 3), (_) => _refresh());
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  Future<void> _refresh() async {
    int status = 0;
    bool? keyConfirmed;
    try {
      final m =
          jsonDecode(await bind.mainGetConnectStatus()) as Map<String, dynamic>;
      status = (m['status_num'] as int?) ?? 0;
      if (m.containsKey('key_confirmed')) {
        keyConfirmed = m['key_confirmed'] == true;
      }
    } catch (_) {}
    if (!mounted) return;
    if (status != _status || keyConfirmed != _keyConfirmed) {
      setState(() {
        _status = status;
        _keyConfirmed = keyConfirmed;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final keyConfirmed = _keyConfirmed;
    if (_status != 1 || keyConfirmed == null) return const SizedBox.shrink();
    final String label;
    final String tip;
    final bool ok;
    if (!keyConfirmed) {
      label = 'Not registered';
      tip = 'nemo_reg_not_tip';
      ok = false;
    } else if (bind.mainNemoDeviceKeyPresent()) {
      label = 'Registered';
      tip = 'nemo_reg_ok_tip';
      ok = true;
    } else {
      label = 'No device key';
      tip = 'nemo_reg_nokey_tip';
      ok = false;
    }
    // A phone has no hover: the explanation opens on tap.
    return Tooltip(
      message: translate(tip),
      triggerMode: TooltipTriggerMode.tap,
      child: Text(translate(label),
          style: TextStyle(
              fontWeight: FontWeight.bold,
              color: ok ? _kNemoGreen : kColorWarn)),
    );
  }
}

// ---------------------------------------------------------------------------
// Direct / Relay badge of a session (R6).
// ---------------------------------------------------------------------------

/// Green "Direct" / orange "Relay" chip for the session with [id]; the full connection
/// text opens on tap. Hidden until the connection type is known.
class NemoSessionConnTypeBadge extends StatelessWidget {
  final String id;
  const NemoSessionConnTypeBadge({Key? key, required this.id})
      : super(key: key);

  static const Color _directColor = Color(0xFF2E9E5B);
  static const Color _relayColor = Color(0xFFD98324);

  @override
  Widget build(BuildContext context) {
    if (!Get.isRegistered<ConnectionType>(tag: ConnectionTypeState.tag(id))) {
      return const Offstage();
    }
    final connectionType = ConnectionTypeState.find(id);
    return Obx(() {
      if (!connectionType.isValid()) return const Offstage();
      final secure = connectionType.secure.value == ConnectionType.strSecure;
      final direct = connectionType.direct.value == ConnectionType.strDirect;
      return Tooltip(
        message:
            getConnectionText(secure, direct, connectionType.stream_type.value),
        triggerMode: TooltipTriggerMode.tap,
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 3),
          decoration: BoxDecoration(
            color: direct ? _directColor : _relayColor,
            borderRadius: BorderRadius.circular(4),
          ),
          child: Text(
            translate(direct ? 'Direct' : 'Relay'),
            style: const TextStyle(
              color: Colors.white,
              fontSize: 12,
              fontWeight: FontWeight.bold,
            ),
          ),
        ),
      );
    });
  }
}
