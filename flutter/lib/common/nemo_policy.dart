// TBFDesk: connect-time policy checks (FLUTTER-PORT A13). Port of createNewConnect and
// its helpers in src/ui/index.tis. client.rs enforces the same rules again in Rust; these
// checks give the user the reason before a session window opens.

import 'package:flutter_hbb/common.dart' show translate;
import 'package:flutter_hbb/models/platform_model.dart';

/// Why the server's policy is not applied on this computer ("" = it is), from the
/// poller's "nemo-policy-problem" ("code|detail"). Same wording as Sciter's
/// nemoPolicyProblemText (src/ui/index.tis).
String nemoPolicyProblemText(String raw) {
  if (raw.isEmpty) return '';
  final i = raw.indexOf('|');
  final code = i < 0 ? raw : raw.substring(0, i);
  final detail = i < 0 ? '' : raw.substring(i + 1);
  final String why;
  switch (code) {
    case 'stale':
      why = translate('nemo_policy_clock_ahead').replaceAll('{min}', detail);
      break;
    case 'future':
      why = translate('nemo_policy_clock_behind').replaceAll('{min}', detail);
      break;
    case 'rollback':
      why = translate('nemo_policy_rollback');
      break;
    case 'signature':
      why = translate('nemo_policy_signature');
      break;
    case 'failed':
      why = '${translate('nemo_policy_failed')} $detail';
      break;
    default:
      why = '($code)';
  }
  return '${translate('nemo_policy_not_applied')} $why';
}

const String kNemoCompanyNetworkOnly = 'nemo-company-network-only';
const String kNemoOutboundEnabled = 'nemo-outbound-enabled';
const String kNemoOutboundTargets = 'nemo-outbound-targets';

String _opt(String key) => bind.mainGetOptionSync(key: key).trim();

/// The server is locked by a `host=…,key=…` executable name AND no imported setup string
/// has overridden it (common::nemo_exe_custom_server_configured — the rule the Rust side
/// enforces when it drops / re-writes the server options).
Future<bool> nemoExeServerSettingsLocked() async => bind.mainNemoExeServerLocked();

bool nemoCompanyNetworkOnly() => _opt(kNemoCompanyNetworkOnly) == 'Y';

bool nemoOutboundEnabled() => _opt(kNemoOutboundEnabled) != 'N';

bool nemoOutboundTargetAllowed(String id) {
  final targets = _opt(kNemoOutboundTargets);
  if (targets.isEmpty) return true;
  for (final t in targets.split(RegExp(r'[,\s;]+'))) {
    final target = t.trim();
    if (target == '*' || target == id) return true;
  }
  return false;
}

bool _idUsesPublicServer(String id) {
  final at = id.indexOf('@');
  if (at < 0) return false;
  return id.substring(at + 1).split('?')[0].trim().toLowerCase() == 'public';
}

/// Untranslated error text when policy forbids connecting to [rawId], else null.
/// [handledId] is the id after relay handling (what is actually dialled).
Future<String?> nemoConnectPolicyError(String rawId, String handledId) async {
  if (!nemoOutboundEnabled()) {
    return 'Outgoing connections are disabled by TBF policy';
  }
  final exeLocked = await nemoExeServerSettingsLocked();
  if (_idUsesPublicServer(rawId) && (exeLocked || nemoCompanyNetworkOnly())) {
    return 'Public network access is disabled by TBF company network mode';
  }
  if (nemoCompanyNetworkOnly() &&
      !exeLocked &&
      _opt('custom-rendezvous-server').isEmpty) {
    return 'Company network only requires an ID server';
  }
  if (!nemoOutboundTargetAllowed(handledId)) {
    return 'Target is not allowed by TBF policy';
  }
  return null;
}
