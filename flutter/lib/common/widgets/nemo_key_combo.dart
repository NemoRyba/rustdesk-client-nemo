// TBFDesk: "Send key combination" -- any modifier set plus any key, for when the local
// keyboard cannot deliver it (the local OS grabs Win+L, Alt+Tab, Ctrl+Alt+F1, a phone has
// no F-keys, ...). Ctrl+Alt+Del keeps its own entry (Windows needs the SAS for it).
//
// Remote desktop session: sent with session_input_key -- the main key "pressed" with the
// modifiers as flags (the way the mobile soft keyboard sends combinations); AltGr as
// right-Alt down / key / right-Alt up.
// Console (terminal) session: the xterm byte sequence for the combination (Ctrl+letter =
// control character, Alt = ESC prefix, modified arrows/F-keys = CSI 1;<mod>).
//
// The Sciter UI has the same dialog (src/ui/header.tis, nemoKeyCombo); its console runs
// in the computer's own terminal window, where combinations are typed natively.
import 'dart:convert';

import 'package:collection/collection.dart';
import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/models/platform_model.dart';
import 'package:flutter_hbb/models/terminal_model.dart';

const String _kRecentOption = 'nemo-key-combo-recent';
const int _kMaxRecent = 8;

class NemoKey {
  final String label;
  final String vk; // name for session_input_key (KEY_MAP in src/client.rs)
  const NemoKey(this.label, this.vk);
}

final List<NemoKey> nemoComboKeys = [
  for (var c = 'A'.codeUnitAt(0); c <= 'Z'.codeUnitAt(0); c++)
    NemoKey(String.fromCharCode(c), 'VK_${String.fromCharCode(c)}'),
  for (var d = 0; d <= 9; d++) NemoKey('$d', 'VK_$d'),
  for (var f = 1; f <= 12; f++) NemoKey('F$f', 'VK_F$f'),
  const NemoKey('Esc', 'VK_ESCAPE'),
  const NemoKey('Tab', 'VK_TAB'),
  const NemoKey('Enter', 'VK_RETURN'),
  const NemoKey('Backspace', 'VK_BACK'),
  const NemoKey('Entf / Del', 'VK_DELETE'),
  const NemoKey('Einfg / Ins', 'VK_INSERT'),
  const NemoKey('Pos1 / Home', 'VK_HOME'),
  const NemoKey('Ende / End', 'VK_END'),
  const NemoKey('Bild ↑ / PgUp', 'VK_PRIOR'),
  const NemoKey('Bild ↓ / PgDn', 'VK_NEXT'),
  const NemoKey('↑', 'VK_UP'),
  const NemoKey('↓', 'VK_DOWN'),
  const NemoKey('←', 'VK_LEFT'),
  const NemoKey('→', 'VK_RIGHT'),
  const NemoKey('Leertaste / Space', 'VK_SPACE'),
  const NemoKey('Druck / Print', 'VK_SNAPSHOT'),
  const NemoKey('Pause', 'VK_PAUSE'),
  const NemoKey('Rollen / Scroll Lock', 'VK_SCROLL'),
  const NemoKey('Menü / Menu', 'Apps'),
  const NemoKey('Win', 'Meta'),
  const NemoKey('-', 'VK_MINUS'),
  const NemoKey('+', 'VK_PLUS'),
  const NemoKey(',', 'VK_COMMA'),
  const NemoKey('/', 'VK_SLASH'),
];

class NemoCombo {
  bool ctrl, alt, shift, win, altgr;
  String vk;
  NemoCombo(
      {this.ctrl = false,
      this.alt = false,
      this.shift = false,
      this.win = false,
      this.altgr = false,
      required this.vk});

  NemoKey? get key => nemoComboKeys.firstWhereOrNull((k) => k.vk == vk);

  String get label => [
        if (ctrl) translate('nemo_key_ctrl'),
        if (alt) 'Alt',
        if (altgr) 'AltGr',
        if (shift) translate('nemo_key_shift'),
        if (win) 'Win',
        key?.label ?? vk,
      ].join(' + ');

  String encode() =>
      '${ctrl ? 'c' : ''}${alt ? 'a' : ''}${shift ? 's' : ''}${win ? 'w' : ''}${altgr ? 'g' : ''}:$vk';

  static NemoCombo? decode(String s) {
    final i = s.indexOf(':');
    if (i < 0) return null;
    final m = s.substring(0, i);
    final vk = s.substring(i + 1);
    if (nemoComboKeys.every((k) => k.vk != vk)) return null;
    return NemoCombo(
        ctrl: m.contains('c'),
        alt: m.contains('a'),
        shift: m.contains('s'),
        win: m.contains('w'),
        altgr: m.contains('g'),
        vk: vk);
  }

  /// The xterm byte sequence for a console session, or null if the combination has no
  /// terminal form (Win / AltGr / Print / Pause / Menu / Scroll Lock).
  String? terminalSequence() {
    if (win || altgr) return null;
    final mod = 1 + (shift ? 1 : 0) + (alt ? 2 : 0) + (ctrl ? 4 : 0);
    String csi(String finalChar) =>
        mod == 1 ? '\x1b[$finalChar' : '\x1b[1;$mod$finalChar';
    String tilde(int n) => mod == 1 ? '\x1b[$n~' : '\x1b[$n;$mod~';
    String ss3(String c) => mod == 1 ? '\x1bO$c' : '\x1b[1;$mod$c';
    String withAlt(String s) => alt ? '\x1b$s' : s;
    if (vk.length == 4 && vk.startsWith('VK_')) {
      final ch = vk.substring(3);
      final code = ch.codeUnitAt(0);
      if (code >= 0x41 && code <= 0x5a) {
        // letter
        if (ctrl) return withAlt(String.fromCharCode(code & 0x1f));
        return withAlt(shift ? ch : ch.toLowerCase());
      }
      if (code >= 0x30 && code <= 0x39) return withAlt(ch); // digit
    }
    switch (vk) {
      case 'VK_UP':
        return csi('A');
      case 'VK_DOWN':
        return csi('B');
      case 'VK_RIGHT':
        return csi('C');
      case 'VK_LEFT':
        return csi('D');
      case 'VK_HOME':
        return csi('H');
      case 'VK_END':
        return csi('F');
      case 'VK_INSERT':
        return tilde(2);
      case 'VK_DELETE':
        return tilde(3);
      case 'VK_PRIOR':
        return tilde(5);
      case 'VK_NEXT':
        return tilde(6);
      case 'VK_F1':
        return ss3('P');
      case 'VK_F2':
        return ss3('Q');
      case 'VK_F3':
        return ss3('R');
      case 'VK_F4':
        return ss3('S');
      case 'VK_F5':
        return tilde(15);
      case 'VK_F6':
        return tilde(17);
      case 'VK_F7':
        return tilde(18);
      case 'VK_F8':
        return tilde(19);
      case 'VK_F9':
        return tilde(20);
      case 'VK_F10':
        return tilde(21);
      case 'VK_F11':
        return tilde(23);
      case 'VK_F12':
        return tilde(24);
      case 'VK_ESCAPE':
        return withAlt('\x1b');
      case 'VK_TAB':
        return shift ? '\x1b[Z' : withAlt('\t');
      case 'VK_RETURN':
        return withAlt('\r');
      case 'VK_BACK':
        return withAlt(ctrl ? '\x08' : '\x7f');
      case 'VK_SPACE':
        return withAlt(ctrl ? '\x00' : ' ');
      case 'VK_MINUS':
        return withAlt('-');
      case 'VK_PLUS':
        return withAlt('+');
      case 'VK_COMMA':
        return withAlt(',');
      case 'VK_SLASH':
        return withAlt(ctrl ? '\x1f' : '/');
    }
    return null;
  }

  /// Send it into a remote desktop session.
  void sendToSession(SessionID sessionId) {
    if (altgr) {
      bind.sessionInputKey(
          sessionId: sessionId,
          name: 'RAlt',
          down: true,
          press: false,
          alt: false,
          ctrl: false,
          shift: false,
          command: false);
    }
    bind.sessionInputKey(
        sessionId: sessionId,
        name: vk,
        down: false,
        press: true,
        alt: alt,
        ctrl: ctrl,
        shift: shift,
        command: win);
    if (altgr) {
      bind.sessionInputKey(
          sessionId: sessionId,
          name: 'RAlt',
          down: false,
          press: false,
          alt: false,
          ctrl: false,
          shift: false,
          command: false);
    }
  }
}

List<NemoCombo> _loadRecent() {
  try {
    final raw = bind.mainGetLocalOption(key: _kRecentOption);
    if (raw.isEmpty) return [];
    return (jsonDecode(raw) as List)
        .map((e) => NemoCombo.decode(e.toString()))
        .whereType<NemoCombo>()
        .toList();
  } catch (_) {
    return [];
  }
}

void _remember(NemoCombo c) {
  final list = _loadRecent().where((e) => e.encode() != c.encode()).toList();
  list.insert(0, c);
  bind.mainSetLocalOption(
      key: _kRecentOption,
      value: jsonEncode(list.take(_kMaxRecent).map((e) => e.encode()).toList()));
}

/// The picker. Exactly one of [sessionId] (remote desktop session) or [terminal]
/// (console session) is used.
Future<void> showNemoKeyComboDialog(
    {SessionID? sessionId, TerminalModel? terminal}) async {
  final isTerminal = terminal != null;
  var combo = NemoCombo(vk: 'VK_DELETE');
  var recent = _loadRecent();
  String? error;

  bool send(NemoCombo c) {
    if (isTerminal) {
      final seq = c.terminalSequence();
      if (seq == null) return false;
      terminal.sendVirtualKey(seq);
    } else if (sessionId != null) {
      c.sendToSession(sessionId);
    }
    _remember(c);
    return true;
  }

  await gFFI.dialogManager.show((setState, close, context) {
    Widget mod(String label, bool value, void Function(bool) set,
        {bool enabled = true}) {
      return FilterChip(
        label: Text(label),
        selected: value,
        onSelected: enabled ? (v) => setState(() => set(v)) : null,
      );
    }

    void submit() {
      if (send(combo)) {
        close();
      } else {
        setState(() => error = translate('nemo_key_combo_no_terminal'));
      }
    }

    return CustomAlertDialog(
      title: Text(translate('nemo_key_combo')),
      content: ConstrainedBox(
        constraints: const BoxConstraints(minWidth: 320, maxWidth: 460),
        child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Wrap(spacing: 6, runSpacing: 6, children: [
                mod(translate('nemo_key_ctrl'), combo.ctrl, (v) => combo.ctrl = v),
                mod('Alt', combo.alt, (v) => combo.alt = v),
                mod(translate('nemo_key_shift'), combo.shift,
                    (v) => combo.shift = v),
                mod('Win', combo.win, (v) => combo.win = v,
                    enabled: !isTerminal),
                mod('AltGr', combo.altgr, (v) => combo.altgr = v,
                    enabled: !isTerminal),
              ]),
              const SizedBox(height: 12),
              Text(translate('nemo_key')),
              DropdownButton<String>(
                isExpanded: true,
                value: combo.vk,
                items: nemoComboKeys
                    .map((k) => DropdownMenuItem(value: k.vk, child: Text(k.label)))
                    .toList(),
                onChanged: (v) => setState(() {
                  if (v != null) combo.vk = v;
                  error = null;
                }),
              ),
              const SizedBox(height: 8),
              Text(combo.label,
                  style: const TextStyle(fontWeight: FontWeight.bold)),
              if (error != null)
                Padding(
                  padding: const EdgeInsets.only(top: 6),
                  child: Text(error!,
                      style: TextStyle(color: Theme.of(context).colorScheme.error)),
                ),
              if (recent.isNotEmpty) ...[
                const SizedBox(height: 12),
                Text(translate('nemo_key_combo_recent')),
                const SizedBox(height: 4),
                Wrap(
                  spacing: 6,
                  runSpacing: 6,
                  children: recent
                      .map((c) => ActionChip(
                            label: Text(c.label),
                            onPressed: () {
                              if (send(c)) {
                                close();
                              } else {
                                setState(() =>
                                    error = translate('nemo_key_combo_no_terminal'));
                              }
                            },
                          ))
                      .toList(),
                ),
              ],
            ],
          ),
        ),
      ),
      actions: [
        dialogButton('Cancel', onPressed: close, isOutline: true),
        dialogButton('nemo_key_combo_send', onPressed: submit),
      ],
      onSubmit: submit,
      onCancel: close,
    );
  });
}
