// TBFDesk: the full-window gates in front of the home page (FLUTTER-PORT A1, A2, A4, A19).
// Port of nemoEnforceLogin / nemoDevKeyGateCard / nemoClaimGateCard / the login gate in
// App.render (src/ui/index.tis).
//
// Order, as in Sciter: no valid device key -> provisioning card; key present but the
// pairing is pending / refused -> claim card; server requires sign-in and nobody is
// signed in -> sign-in page; otherwise the real home page. Re-checked every 3 s (the key
// can be provisioned by the service, a claim flips when the administrator acts) and at
// once after an import (nemoGateRefresh) or a sign-in / sign-out (userName).

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/common/widgets/nemo_import_dialog.dart';
import 'package:flutter_hbb/common/widgets/nemo_login.dart';
import 'package:flutter_hbb/models/platform_model.dart';
import 'package:get/get.dart';

const Color kNemoAccent = Color(0xFF0B7285);

enum _NemoGateState { none, noKey, claimPending, claimDenied, login }

_NemoGateState _currentGate({bool requireDeviceKey = true}) {
  // Mobile (FLUTTER-PORT §10 mobile 1): fleet is optional, a phone without a device key
  // is a normal standalone client; the claim and sign-in gates still apply.
  if (!bind.mainNemoDeviceKeyPresent()) {
    return requireDeviceKey ? _NemoGateState.noKey : _NemoGateState.none;
  }
  final claim = bind.mainNemoClaimStatus().trim();
  if (claim == 'pending') return _NemoGateState.claimPending;
  if (claim == 'denied') return _NemoGateState.claimDenied;
  if (nemoLoginRequired() && !gFFI.userModel.isLogin) {
    return _NemoGateState.login;
  }
  return _NemoGateState.none;
}

class NemoGate extends StatefulWidget {
  final Widget child;

  /// false on mobile: without a device key the app runs as a standalone client.
  final bool requireDeviceKey;

  const NemoGate({Key? key, required this.child, this.requireDeviceKey = true})
      : super(key: key);

  @override
  State<NemoGate> createState() => _NemoGateState2();
}

class _NemoGateState2 extends State<NemoGate> {
  Timer? _timer;
  late _NemoGateState _gate;

  @override
  void initState() {
    super.initState();
    _gate = _currentGate(requireDeviceKey: widget.requireDeviceKey);
    _timer = Timer.periodic(const Duration(seconds: 3), (_) => _recheck());
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  // Re-render on a transition only.
  void _recheck() {
    if (!mounted) return;
    final g = _currentGate(requireDeviceKey: widget.requireDeviceKey);
    if (g != _gate) setState(() => _gate = g);
  }

  @override
  Widget build(BuildContext context) {
    return Obx(() {
      // Subscribe: an import or a sign-in/-out re-evaluates immediately.
      nemoGateRefresh.value;
      gFFI.userModel.userName.value;
      _gate = _currentGate(requireDeviceKey: widget.requireDeviceKey);
      final gated = _gate != _NemoGateState.none;
      // The real home page stays MOUNTED behind a gate -- not painted, no pointer, no
      // keyboard focus (nothing behind the gate is usable), but its initState runs. On
      // desktop it registers the main window's multi-window handler, which session
      // windows call (open a display in its own window, window info, ...). Without it a
      // session started by link / command line while the gate shows lost those features
      // ("windows" display mode opened no second window).
      return Stack(fit: StackFit.expand, children: [
        ExcludeFocus(
          excluding: gated,
          child: IgnorePointer(
            ignoring: gated,
            child: Offstage(
              offstage: gated,
              child: TickerMode(enabled: !gated, child: widget.child),
            ),
          ),
        ),
        if (gated) _gateWidget(),
      ]);
    });
  }

  Widget _gateWidget() {
      switch (_gate) {
        case _NemoGateState.none:
          return const SizedBox.shrink();
        case _NemoGateState.login:
          return NemoLoginPage(required: true, onLoggedIn: _recheck);
        case _NemoGateState.noKey:
          return _NemoGateCard(
            heading: translate('This device is not set up yet'),
            text:
                '${translate('A device key issued by your TBFDesk server is required before this client can be used.')}\n'
                '${translate('Your administrator can give you a setup string instead, which also fills in the server addresses.')}',
            primary: true,
          );
        case _NemoGateState.claimPending:
          return _NemoGateCard(
            heading: translate('Waiting for approval by your administrator'),
            text: translate(
                'This device has asked to be registered with its device key. Your administrator has to confirm it once; this screen clears by itself within a minute of that.'),
            primary: false,
          );
        case _NemoGateState.claimDenied:
          return _NemoGateCard(
            heading: translate('This device was not approved'),
            text: translate(
                'Your administrator refused this device key. Ask them to clear the request or to issue a new key for this machine.'),
            primary: false,
          );
      }
  }
}

/// Small grey "Build <id>" at the bottom-left of the main window and every gate.
class NemoBuildIdLabel extends StatelessWidget {
  const NemoBuildIdLabel({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    final id = bind.mainGetBuildId();
    if (id.isEmpty) return const SizedBox.shrink();
    return Tooltip(
      message: translate('Build'),
      child: Text('Build $id',
          style: const TextStyle(fontSize: 10, color: Colors.grey)),
    );
  }
}

class _NemoGateCard extends StatelessWidget {
  final String heading;
  final String text;
  final bool primary;

  const _NemoGateCard(
      {required this.heading, required this.text, required this.primary});

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final button = SizedBox(
      width: double.infinity,
      child: primary
          ? ElevatedButton(
              style: ElevatedButton.styleFrom(
                backgroundColor: kNemoAccent,
                foregroundColor: Colors.white,
                padding: const EdgeInsets.symmetric(vertical: 12),
                shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(6)),
              ),
              onPressed: () => showNemoImportDialog(context),
              child: Text(translate('Import setup string or device key'),
                  textAlign: TextAlign.center,
                  style: const TextStyle(
                      fontSize: 14, fontWeight: FontWeight.bold)),
            )
          : OutlinedButton(
              style: OutlinedButton.styleFrom(
                foregroundColor: kNemoAccent,
                side: const BorderSide(color: kNemoAccent),
                padding: const EdgeInsets.symmetric(vertical: 10),
                shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(6)),
              ),
              onPressed: () => showNemoImportDialog(context),
              child: Text(translate('Import setup string or device key'),
                  textAlign: TextAlign.center),
            ),
    );
    return Container(
      color: isDark ? null : const Color(0xFFF0F2F5),
      child: Stack(
        children: [
          Center(
            child: SingleChildScrollView(
              child: Container(
                width: 380,
                padding: const EdgeInsets.fromLTRB(42, 40, 42, 40),
                decoration: BoxDecoration(
                  color: isDark ? Theme.of(context).cardColor : Colors.white,
                  border: Border.all(color: const Color(0xFFE2E6EA)),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const Text('TBFDesk',
                        style: TextStyle(
                            fontSize: 30,
                            fontWeight: FontWeight.bold,
                            color: kNemoAccent)),
                    const SizedBox(height: 6),
                    Text(heading,
                        textAlign: TextAlign.center,
                        style: const TextStyle(
                            fontSize: 16, fontWeight: FontWeight.bold)),
                    const SizedBox(height: 10),
                    Text(text,
                        textAlign: TextAlign.center,
                        style: const TextStyle(
                            fontSize: 13, color: Color(0xFF667788))),
                    const SizedBox(height: 24),
                    button,
                  ],
                ),
              ),
            ),
          ),
          const Positioned(left: 10, bottom: 6, child: NemoBuildIdLabel()),
        ],
      ),
    );
  }
}
