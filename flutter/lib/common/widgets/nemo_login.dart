// TBFDesk: sign-in card (sealed login) and server certificate box.
// Port of the Sciter login gate (src/ui/index.tis: nemoGateSubmit,
// nemoApplyGateServer, nemoRefreshCertInfo, nemoCertBoxVnode).

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/common/hbbs/hbbs.dart';
import 'package:flutter_hbb/common/widgets/login.dart'
    show verificationCodeDialog;
import 'package:flutter_hbb/common/widgets/nemo_import_dialog.dart';
import 'package:flutter_hbb/consts.dart';
import 'package:flutter_hbb/models/platform_model.dart';
import 'package:flutter_hbb/models/user_model.dart';

const String _kOptRequireLogin = 'nemo-require-login';
const String _kOptManagementServer = 'nemo-management-server';

const Color _kAccent = Color(0xFF0B7285);
const Color _kPageBg = Color(0xFFF0F2F5);
const Color _kCardBorder = Color(0xFFE2E6EA);
const Color _kInputBorder = Color(0xFFCCD2D8);
const Color _kLabel = Color(0xFF555566);
const Color _kMuted = Color(0xFF9AA7B2);
const Color _kError = Color(0xFFD4380D);

/// The server demands a signed-in user before the client may be used.
bool nemoLoginRequired() =>
    bind.mainGetOptionSync(key: _kOptRequireLogin) == 'Y';

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

class NemoHttpResult {
  final int status;
  final String body;
  NemoHttpResult(this.status, this.body);
}

/// POST through the Rust HTTP client, always (not dart:io): it honours
/// allow-insecure-tls-fallback, the pinned nemo-api certificate and the proxy
/// settings, which the self-signed TBFDesk API needs.
Future<NemoHttpResult> nemoHttpPost(String url,
    {Map<String, String>? headers, String body = ''}) async {
  headers ??= {'Content-Type': 'application/json'};
  await bind.mainHttpRequest(
      url: url, method: 'post', body: body, header: jsonEncode(headers));
  final deadline = DateTime.now().add(const Duration(seconds: 60));
  String res;
  while (true) {
    final r = await bind.mainGetHttpStatus(url: url);
    if (r == null) throw Exception('The HTTP request failed');
    res = r;
    if (res != ' ') break;
    if (DateTime.now().isAfter(deadline)) throw Exception('Timeout');
    await Future.delayed(const Duration(milliseconds: 100));
  }
  final dynamic parsed;
  try {
    parsed = jsonDecode(res);
  } catch (_) {
    // On a transport error Rust stores the error text instead of JSON.
    throw Exception(res);
  }
  if (parsed is! Map || parsed['status_code'] is! int) throw Exception(res);
  return NemoHttpResult(
      parsed['status_code'] as int, (parsed['body'] ?? '').toString());
}

String _nemoNetErr(String api, Object e) {
  var err = e.toString();
  if (err.startsWith('Exception: ')) err = err.substring('Exception: '.length);
  err = translate(err);
  if (!api.contains('rustdesk')) err = '$api, $err';
  return err;
}

/// POST JSON to `<api><path>`, decode the JSON reply. Throws [RequestException].
Future<Map<String, dynamic>> _nemoPostJson(
    String api, String path, Map<String, dynamic> payload) async {
  final NemoHttpResult resp;
  try {
    resp = await nemoHttpPost('$api$path', body: jsonEncode(payload));
  } catch (e) {
    throw RequestException(0, _nemoNetErr(api, e));
  }
  Map<String, dynamic>? body;
  try {
    final v = jsonDecode(resp.body);
    if (v is Map<String, dynamic>) body = v;
  } catch (_) {}
  if (body == null) {
    throw RequestException(resp.status,
        resp.status != 200 ? 'HTTP ${resp.status}' : 'Invalid response');
  }
  if (resp.status != 200) {
    final err = body['error'];
    throw RequestException(resp.status,
        err != null ? translate(err.toString()) : 'HTTP ${resp.status}');
  }
  return body;
}

Map<String, dynamic> _nemoDeviceInfo() {
  try {
    final v = jsonDecode(bind.mainGetLoginDeviceInfo());
    if (v is Map<String, dynamic>) return v;
  } catch (e) {
    debugPrint('Failed to decode device info: $e');
  }
  return {};
}

/// The /api/login exchange. A request carrying a password is only ever sent
/// sealed to the server's verified login key (no plaintext fallback). A sealed
/// session token in the reply is opened; failing to open it is final.
/// Returns the reply body with `access_token` filled in. Throws [RequestException].
Future<Map<String, dynamic>> nemoLoginRequest(
    String api, LoginRequest req) async {
  final Map<String, dynamic> payload;
  if (req.password != null) {
    final keyData = await _nemoPostJson(api, '/api/login-key', {});
    final key = (keyData['key'] ?? '').toString();
    final signedKey = (keyData['signed_key'] ?? '').toString();
    final sealed = signedKey.isEmpty
        ? ''
        : await bind.mainNemoSealLogin(
            key: key,
            signedKey: signedKey,
            username: req.username ?? '',
            password: req.password!);
    if (sealed.isEmpty) {
      throw RequestException(
          0,
          translate(
              'Secure login unavailable: the server key could not be verified.'));
    }
    payload = {
      'sealed': sealed,
      'id': req.id,
      'uuid': req.uuid,
      'type': HttpType.kAuthReqTypeAccount,
      'deviceInfo': _nemoDeviceInfo(),
    };
  } else {
    // Verification-code step: no password in it.
    payload = req.toJson();
  }
  final body = await _nemoPostJson(api, '/api/login', payload);
  final error = body['error'];
  if (error != null) throw RequestException(0, translate(error.toString()));
  final sealedToken = (body['sealed_access_token'] ?? '').toString();
  if (sealedToken.isNotEmpty) {
    final token = await bind.mainNemoOpenLoginReply(sealed: sealedToken);
    if (token.isEmpty) {
      throw RequestException(
          0,
          translate(
              'Secure login unavailable: the session token could not be opened.'));
    }
    body['access_token'] = token;
    body.remove('sealed_access_token');
  }
  if (body['type'] == null && body['access_token'] != null) {
    body['type'] = HttpType.kAuthResTypeToken;
  }
  return body;
}

/// Sign in with the sealed flow, including the email/2FA step.
/// null = signed in; otherwise the message to show ('' = cancelled).
Future<String?> nemoSealedLogin(
    {required String api,
    required String username,
    required String password}) async {
  try {
    final resp = await gFFI.userModel.login(
        LoginRequest(
            username: username,
            password: password,
            id: await bind.mainGetMyId(),
            uuid: await bind.mainGetUuid(),
            type: HttpType.kAuthReqTypeAccount),
        apiServer: api);
    switch (resp.type) {
      case HttpType.kAuthResTypeToken:
        final token = resp.access_token ?? '';
        if (token.isNotEmpty) {
          await bind.mainSetLocalOption(key: 'access_token', value: token);
          await bind.mainSetLocalOption(
              key: 'user_info', value: jsonEncode(resp.user ?? {}));
          UserModel.updateOtherModels();
          return null;
        }
        break;
      case HttpType.kAuthResTypeEmailCheck:
        final bool isEmail;
        if (resp.tfa_type == null ||
            resp.tfa_type == HttpType.kAuthResTypeEmailCheck) {
          isEmail = true;
        } else if (resp.tfa_type == HttpType.kAuthResTypeTfaCheck) {
          isEmail = false;
        } else {
          return 'Failed, bad tfa type from server';
        }
        final ok =
            await verificationCodeDialog(resp.user, resp.secret, isEmail);
        if (ok == true) {
          UserModel.updateOtherModels();
          return null;
        }
        return '';
    }
    return 'Failed, bad response from server';
  } on RequestException catch (e) {
    return e.cause;
  } catch (e) {
    return 'Unknown Error: $e';
  }
}

// ---------------------------------------------------------------------------
// Server field
// ---------------------------------------------------------------------------

class _NemoServer {
  final String host;
  final String api;
  _NemoServer(this.host, this.api);
}

/// Bare host -> https://host:21120; a full http(s):// URL is kept as is.
_NemoServer _nemoDeriveApiUrl(String val) {
  val = val.trim();
  if (val.startsWith('http://') || val.startsWith('https://')) {
    var rest = val.substring(val.indexOf('://') + 3);
    final slash = rest.indexOf('/');
    if (slash >= 0) rest = rest.substring(0, slash);
    final colon = rest.indexOf(':');
    return _NemoServer(colon >= 0 ? rest.substring(0, colon) : rest, val);
  }
  final colon = val.indexOf(':');
  return _NemoServer(colon >= 0 ? val.substring(0, colon) : val,
      'https://$val${colon >= 0 ? '' : ':21120'}');
}

String _nemoGateServerValueSync() {
  var v = bind.mainGetOptionSync(key: 'api-server').trim();
  if (v.isEmpty) {
    v = bind.mainGetOptionSync(key: 'custom-rendezvous-server').trim();
  }
  return v;
}

Future<String> _nemoGateServerValue() async {
  var v = _nemoGateServerValueSync();
  if (v.isEmpty) v = (await bind.mainGetApiServer()).trim();
  if (v.isEmpty) v = bind.mainNemoConfiguredApiServer().trim();
  return v;
}

/// Save the gate's server field: ID server, api-server and management server.
/// An existing api-server on the same host is kept (its port can't be guessed).
Future<void> _nemoApplyGateServer(String val) async {
  val = val.trim();
  if (val.isEmpty) return;
  final d = _nemoDeriveApiUrl(val);
  final curId = bind.mainGetOptionSync(key: 'custom-rendezvous-server').trim();
  if (curId.isEmpty || _nemoDeriveApiUrl(curId).host != d.host) {
    await bind.mainSetOption(key: 'custom-rendezvous-server', value: d.host);
  }
  final curApi = bind.mainGetOptionSync(key: 'api-server').trim();
  if (curApi.isEmpty || _nemoDeriveApiUrl(curApi).host != d.host) {
    await bind.mainSetOption(key: 'api-server', value: d.api);
    await bind.mainSetOption(key: _kOptManagementServer, value: d.api);
  }
  await _nemoInitInsecureTlsDefault();
}

// ---------------------------------------------------------------------------
// Insecure TLS
// ---------------------------------------------------------------------------

bool _nemoInsecureTlsValue() =>
    bind.mainGetOptionSync(key: kOptionAllowInsecureTLSFallback).trim() == 'Y';

bool _nemoInsecureTlsManaged() =>
    bind.mainIsOptionFixed(key: kOptionAllowInsecureTLSFallback);

/// First-run default: allow the self-signed certificate unless a choice exists
/// or an administrator manages the option.
Future<void> _nemoInitInsecureTlsDefault() async {
  if (_nemoInsecureTlsManaged()) return;
  if (bind.mainGetOptionSync(key: kOptionAllowInsecureTLSFallback).trim() ==
      '') {
    await bind.mainSetOption(key: kOptionAllowInsecureTLSFallback, value: 'Y');
  }
}

// ---------------------------------------------------------------------------
// Certificate probe (cached per server URL, survives rebuilds)
// ---------------------------------------------------------------------------

class _NemoCertProbe extends ChangeNotifier {
  Map<String, dynamic>? data; // /api/tls-cert-info JSON (includes pem)
  String? err;
  String url = '';
  bool probing = false;
  int dots = 0;
  Timer? _timer;

  void refresh(String newUrl, {bool force = false}) {
    if (newUrl.isEmpty) {
      _timer?.cancel();
      data = null;
      err = null;
      url = '';
      probing = false;
      notifyListeners();
      return;
    }
    if (!force && newUrl == url && (data != null || err != null || probing)) {
      notifyListeners();
      return;
    }
    _timer?.cancel();
    data = null;
    err = null;
    url = newUrl;
    probing = true;
    dots = 0;
    notifyListeners();
    final started = newUrl;
    bind.mainNemoCertInfoStart(url: '$newUrl/api/tls-cert-info').then((_) {
      if (url == started) _poll(started);
    });
  }

  void _poll(String forUrl) {
    _timer = Timer(const Duration(milliseconds: 350), () async {
      if (!probing || url != forUrl) return;
      final status = await bind.mainNemoCertInfoResult();
      if (!probing || url != forUrl) return;
      if (status == ' ' || status == '') {
        dots = (dots % 3) + 1;
        notifyListeners();
        _poll(forUrl);
        return;
      }
      Map<String, dynamic>? info;
      try {
        final v = jsonDecode(status);
        if (v is Map<String, dynamic>) info = v;
      } catch (_) {}
      if (info == null || info['error'] != null) {
        err = info != null ? '${info['error']}' : status;
        data = null;
      } else {
        data = info;
        err = null;
      }
      probing = false;
      notifyListeners();
    });
  }
}

final _nemoCertProbe = _NemoCertProbe();

/// SHA-256 fingerprint grouped in runs of 8 bytes so it wraps readably.
String _nemoFmtFp(String fp) {
  final parts = fp.split(':');
  final out = StringBuffer();
  for (var i = 0; i < parts.length; ++i) {
    out.write(parts[i]);
    if (i < parts.length - 1) out.write((i + 1) % 8 == 0 ? ' ' : ':');
  }
  return out.toString();
}

Future<void> _nemoDownloadCert(Map<String, dynamic> info) async {
  final pem = (info['pem'] ?? '').toString();
  if (pem.isEmpty) return;
  final host = (info['server_host'] ?? '').toString();
  var path = await FilePicker.platform.saveFile(
    dialogTitle: translate('Save certificate'),
    fileName: 'tbfdesk-${host.isEmpty ? 'tbfdesk' : host}.crt',
    type: FileType.custom,
    allowedExtensions: ['crt'],
  );
  if (path == null || path.isEmpty) return;
  if (!path.toLowerCase().endsWith('.crt')) path = '$path.crt';
  try {
    await File(path).writeAsString(pem);
  } catch (e) {
    showToast('$e');
  }
}

class _NemoCertBox extends StatelessWidget {
  const _NemoCertBox();

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
        animation: _nemoCertProbe,
        builder: (context, _) {
          final p = _nemoCertProbe;
          if (p.probing || (p.data == null && p.err == null)) {
            final dots = '.' * (p.dots > 0 ? p.dots : 3);
            return _box(
                const Color(0xFFF6F8FA),
                _kCardBorder,
                const Color(0xFF555566),
                Text('${translate('Checking server certificate')}$dots'));
          }
          var title = '';
          var hint = '';
          final lines = <String>[];
          final info = p.data;
          final allowed = _nemoInsecureTlsValue();
          const orange = [
            Color(0xFFFFF8E6),
            Color(0xFFF0D98C),
            Color(0xFF8A6D1A)
          ];
          const red = [Color(0xFFFDECEA), Color(0xFFF3B6AE), Color(0xFFB42318)];
          const green = [
            Color(0xFFEEF8F0),
            Color(0xFFB7DFC0),
            Color(0xFF1A7A34)
          ];
          List<Color> c;
          if (info != null && info['tls'] == true) {
            if (info['self_signed'] == true) {
              if (allowed) {
                c = orange;
                title = translate(
                    'Self-signed certificate - allowed, encrypted but not verified by your OS');
                hint = translate(
                    'This is normal for TBFDesk and safe. Your password stays sealed end-to-end. To remove this warning, install a CA-signed certificate and check the fingerprint matches your server.');
              } else {
                c = red;
                title = translate(
                    'Self-signed certificate - not allowed, sign-in will fail');
                hint = translate(
                    "Insecure TLS is off, so signing in to this self-signed server will fail. Tick 'Allow insecure TLS' above to sign in (your password stays sealed), or install a CA-signed certificate.");
              }
            } else {
              c = green;
              title = translate('Certificate verified - secure connection');
              hint = translate(
                  "This certificate is issued by a trusted authority. You can turn off 'Allow insecure TLS'.");
            }
            final subject = (info['subject'] ?? '').toString();
            final issuer = (info['issuer'] ?? '').toString();
            final sans = info['sans'];
            final fp = (info['fingerprint'] ?? '').toString();
            final notAfter = (info['not_after'] ?? '').toString();
            if (subject.isNotEmpty) {
              lines.add('${translate('Subject')}: $subject');
            }
            if (issuer.isNotEmpty && issuer != subject) {
              lines.add('${translate('Issuer')}: $issuer');
            }
            if (sans is List && sans.isNotEmpty) {
              lines.add('${translate('Names')}: ${sans.join(', ')}');
            }
            if (fp.isNotEmpty) {
              lines.add(
                  '${translate('Fingerprint (SHA-256)')}: ${_nemoFmtFp(fp)}');
            }
            if (notAfter.isNotEmpty) {
              lines.add('${translate('Valid until')}: $notAfter');
            }
            lines.add(allowed
                ? translate('Insecure TLS is currently allowed')
                : translate('Insecure TLS is currently blocked'));
          } else if (info != null) {
            c = red;
            title = translate('The server is not using TLS');
            hint = translate(
                'Credentials would travel unencrypted. Enable TLS on the TBFDesk server (--nemo-api-tls auto).');
          } else {
            c = red;
            title = translate('Could not verify the server certificate');
            if (p.err != null) lines.add(p.err!);
            hint = translate(
                "If this is your TBFDesk server with a self-signed certificate, tick 'Allow insecure TLS' above. For production, install a CA-signed certificate.");
          }
          final bg = c[0], bd = c[1], fg = c[2];
          var text = title;
          for (final l in lines) {
            text += '\n$l';
          }
          if (hint.isNotEmpty) text += '\n\n$hint';
          final hasPem =
              info != null && (info['pem'] ?? '').toString().isNotEmpty;
          return _box(
              bg,
              bd,
              fg,
              Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  SelectableText(text),
                  if (hasPem)
                    Padding(
                      padding: const EdgeInsets.only(top: 8),
                      child: MouseRegion(
                        cursor: SystemMouseCursors.click,
                        child: GestureDetector(
                          onTap: () => _nemoDownloadCert(info!),
                          child: Text(translate('Download certificate'),
                              style: TextStyle(
                                  color: fg,
                                  decoration: TextDecoration.underline,
                                  decorationColor: fg)),
                        ),
                      ),
                    ),
                ],
              ));
        });
  }

  Widget _box(Color bg, Color bd, Color fg, Widget child) {
    return Container(
      width: double.infinity,
      margin: const EdgeInsets.only(top: 16),
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: BoxDecoration(
          color: bg,
          border: Border.all(color: bd),
          borderRadius: BorderRadius.circular(6)),
      child: DefaultTextStyle.merge(
          style: TextStyle(fontSize: 11, height: 1.5, color: fg), child: child),
    );
  }
}

// ---------------------------------------------------------------------------
// Sign-in card
// ---------------------------------------------------------------------------

/// Full-window sign-in screen (login-first gate, or optional sign-in).
class NemoLoginPage extends StatefulWidget {
  const NemoLoginPage(
      {Key? key, required this.required, this.onCancel, this.onLoggedIn})
      : super(key: key);
  final bool required;
  final VoidCallback? onCancel;
  final VoidCallback? onLoggedIn;

  @override
  State<NemoLoginPage> createState() => _NemoLoginPageState();
}

class _NemoLoginPageState extends State<NemoLoginPage> {
  @override
  Widget build(BuildContext context) {
    return Theme(
      data: MyTheme.lightTheme,
      child: Material(
        color: _kPageBg,
        child: Stack(
          children: [
            Positioned.fill(
              child: Center(
                child: SingleChildScrollView(
                  padding: const EdgeInsets.all(16),
                  child: _NemoLoginCard(
                      required: widget.required,
                      onCancel: widget.onCancel,
                      onLoggedIn: widget.onLoggedIn),
                ),
              ),
            ),
            const Positioned(left: 8, bottom: 4, child: _NemoBuildId()),
          ],
        ),
      ),
    );
  }
}

class _NemoBuildId extends StatelessWidget {
  const _NemoBuildId();

  @override
  Widget build(BuildContext context) {
    return Tooltip(
      message: translate(
          'Identifies the exact running build (git commit and date).'),
      child: Text('Build ${bind.mainGetBuildId()}',
          style: const TextStyle(fontSize: 11, color: Color(0xCC8A94A0))),
    );
  }
}

/// Optional sign-in in a dialog (Login buttons). true = signed in.
Future<bool?> nemoLoginDialog() {
  return gFFI.dialogManager.show<bool>((setState, close, context) {
    return _nemoDialogBody(
        onCancel: () => close(false), onLoggedIn: () => close(true));
  });
}

/// Optional sign-in in a dialog (Login buttons).
Future<void> showNemoLoginDialog(BuildContext context) async {
  try {
    await nemoLoginDialog();
  } catch (e) {
    // No dialog overlay in this window: use a plain route.
    if (!context.mounted) return;
    await showDialog<bool>(
        context: context,
        barrierDismissible: false,
        builder: (ctx) => _nemoDialogBody(
            onCancel: () => Navigator.of(ctx).pop(false),
            onLoggedIn: () => Navigator.of(ctx).pop(true)));
  }
}

Widget _nemoDialogBody(
    {required VoidCallback onCancel, required VoidCallback onLoggedIn}) {
  return Theme(
    data: MyTheme.lightTheme,
    child: Center(
      child: Material(
        color: Colors.transparent,
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(16),
          child: _NemoLoginCard(
              required: false, onCancel: onCancel, onLoggedIn: onLoggedIn),
        ),
      ),
    ),
  );
}

class _NemoLoginCard extends StatefulWidget {
  const _NemoLoginCard(
      {required this.required, this.onCancel, this.onLoggedIn});
  final bool required;
  final VoidCallback? onCancel;
  final VoidCallback? onLoggedIn;

  @override
  State<_NemoLoginCard> createState() => _NemoLoginCardState();
}

class _NemoLoginCardState extends State<_NemoLoginCard> {
  final _server = TextEditingController();
  final _user = TextEditingController();
  final _pass = TextEditingController();
  final _serverFocus = FocusNode();
  final _userFocus = FocusNode();
  final _passFocus = FocusNode();
  bool _obscure = true;
  bool _busy = false;
  String _error = '';
  Timer? _serverDebounce;

  @override
  void initState() {
    super.initState();
    _user.text = (UserModel.getLocalUserInfo()?['name'] ?? '').toString();
    _server.text = _nemoGateServerValueSync();
    _init();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted) _userFocus.requestFocus();
    });
  }

  Future<void> _init() async {
    await _nemoInitInsecureTlsDefault();
    if (_server.text.trim().isEmpty) {
      final v = await _nemoGateServerValue();
      if (!mounted) return;
      if (_server.text.trim().isEmpty) _server.text = v;
    }
    if (!mounted) return;
    setState(() {});
    _refreshCert();
  }

  @override
  void dispose() {
    _serverDebounce?.cancel();
    _server.dispose();
    _user.dispose();
    _pass.dispose();
    _serverFocus.dispose();
    _userFocus.dispose();
    _passFocus.dispose();
    super.dispose();
  }

  /// The (possibly unsaved) server field first, else the configured api-server.
  Future<String> _gateApiUrl() async {
    final v = _server.text.trim();
    if (v.isNotEmpty) return _nemoDeriveApiUrl(v).api;
    return (await bind.mainGetApiServer()).trim();
  }

  Future<void> _refreshCert({bool force = false}) async {
    final url = await _gateApiUrl();
    _nemoCertProbe.refresh(url, force: force);
  }

  void _onServerChanged(String _) {
    // TBFDesk: re-probe the certificate once the user stops typing.
    _serverDebounce?.cancel();
    _serverDebounce = Timer(const Duration(milliseconds: 800), () {
      if (mounted) _refreshCert();
    });
  }

  Future<void> _toggleInsecureTls() async {
    if (_nemoInsecureTlsManaged()) return;
    await bind.mainSetOption(
        key: kOptionAllowInsecureTLSFallback,
        value: _nemoInsecureTlsValue() ? 'N' : 'Y');
    if (!mounted) return;
    setState(() {});
    _refreshCert();
  }

  Future<void> _submit() async {
    if (_busy) return;
    final name = _user.text.trim();
    final pass = _pass.text;
    if (name.isEmpty) {
      setState(() => _error = translate('Username missed'));
      _userFocus.requestFocus();
      return;
    }
    if (pass.trim().isEmpty) {
      setState(() => _error = translate('Password missed'));
      _passFocus.requestFocus();
      return;
    }
    setState(() {
      _busy = true;
      _error = '';
    });
    await _nemoApplyGateServer(_server.text);
    final api = (await bind.mainGetApiServer()).trim();
    if (!mounted) return;
    if (api.isEmpty) {
      setState(() {
        _busy = false;
        _error = '${translate('API Server')} ?';
      });
      _serverFocus.requestFocus();
      return;
    }
    final err = await nemoSealedLogin(api: api, username: name, password: pass);
    if (!mounted) return;
    setState(() {
      _busy = false;
      _error = err ?? '';
    });
    if (err == null) widget.onLoggedIn?.call();
  }

  Future<void> _import() async {
    await showNemoImportDialog(context);
    if (!mounted) return;
    if (_server.text.trim().isEmpty) {
      _server.text = await _nemoGateServerValue();
    }
    if (!mounted) return;
    setState(() {});
    _refreshCert(force: true);
  }

  InputDecoration _decoration({String? hint, Widget? suffix}) {
    OutlineInputBorder border(Color c) => OutlineInputBorder(
        borderRadius: BorderRadius.circular(6),
        borderSide: BorderSide(color: c));
    return InputDecoration(
      isDense: true,
      hintText: hint,
      hintStyle: const TextStyle(color: _kMuted),
      filled: true,
      fillColor: Colors.white,
      contentPadding: const EdgeInsets.symmetric(horizontal: 10, vertical: 11),
      border: border(_kInputBorder),
      enabledBorder: border(_kInputBorder),
      focusedBorder: border(_kAccent),
      suffixIcon: suffix,
    );
  }

  Widget _label(String text, [String? note]) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 5),
      child: Text.rich(TextSpan(
        style: const TextStyle(fontSize: 12, color: _kLabel),
        children: [
          TextSpan(text: text),
          if (note != null)
            TextSpan(text: ' ($note)', style: const TextStyle(color: _kMuted)),
        ],
      )),
    );
  }

  Widget _tlsControl() {
    final allowed = _nemoInsecureTlsValue();
    if (_nemoInsecureTlsManaged()) {
      return Padding(
        padding: const EdgeInsets.only(top: 8, bottom: 16),
        child: Text(
            '${allowed ? translate('Insecure TLS is currently allowed') : translate('Insecure TLS is currently blocked')} (${translate('managed by your administrator')})',
            style: const TextStyle(fontSize: 11, color: Color(0xFF8A94A0))),
      );
    }
    return Padding(
      padding: const EdgeInsets.only(top: 4, bottom: 10),
      child: InkWell(
        onTap: _busy ? null : _toggleInsecureTls,
        child: Row(
          children: [
            SizedBox(
              width: 28,
              height: 28,
              child: Checkbox(
                value: allowed,
                activeColor: _kAccent,
                onChanged: _busy ? null : (_) => _toggleInsecureTls(),
              ),
            ),
            const SizedBox(width: 4),
            Expanded(
              child: Text(
                  translate('Allow insecure TLS (self-signed certificate)'),
                  style:
                      const TextStyle(fontSize: 12, color: Color(0xFF666677))),
            ),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    const inputStyle = TextStyle(fontSize: 14, color: Colors.black87);
    // 340px content + 42px side padding, like the Sciter card; narrower windows shrink it.
    final card = ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 340 + 84),
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 42, vertical: 40),
          decoration: BoxDecoration(
            color: Colors.white,
            border: Border.all(color: _kCardBorder),
            borderRadius: BorderRadius.circular(10),
          ),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const Text('TBFDesk',
                  textAlign: TextAlign.center,
                  style: TextStyle(
                      fontSize: 30,
                      fontWeight: FontWeight.bold,
                      color: _kAccent)),
              const SizedBox(height: 6),
              Text(translate('Please sign in to continue'),
                  textAlign: TextAlign.center,
                  style:
                      const TextStyle(fontSize: 14, color: Color(0xFF666677))),
              const SizedBox(height: 26),
              _label(translate('Server'),
                  translate('address of your TBFDesk server')),
              TextField(
                controller: _server,
                focusNode: _serverFocus,
                enabled: !_busy,
                style: inputStyle,
                decoration: _decoration(hint: 'tbfdesk.example.com'),
                onChanged: _onServerChanged,
                onSubmitted: (_) => _submit(),
              ).workaroundFreezeLinuxMint(),
              _tlsControl(),
              _label(translate('Username'),
                  translate('use your Windows credentials')),
              TextField(
                controller: _user,
                focusNode: _userFocus,
                enabled: !_busy,
                style: inputStyle,
                decoration: _decoration(),
                onSubmitted: (_) => _submit(),
              ).workaroundFreezeLinuxMint(),
              const SizedBox(height: 16),
              _label(translate('Password')),
              TextField(
                controller: _pass,
                focusNode: _passFocus,
                enabled: !_busy,
                obscureText: _obscure,
                style: inputStyle,
                decoration: _decoration(
                  suffix: IconButton(
                    splashRadius: 16,
                    iconSize: 18,
                    color: const Color(0xFF8A97A3),
                    icon: Icon(
                        _obscure ? Icons.visibility : Icons.visibility_off),
                    onPressed: () => setState(() => _obscure = !_obscure),
                  ),
                ),
                onSubmitted: (_) => _submit(),
              ).workaroundFreezeLinuxMint(),
              const SizedBox(height: 24),
              Center(
                child: ElevatedButton(
                  style: ElevatedButton.styleFrom(
                    backgroundColor: _kAccent,
                    foregroundColor: Colors.white,
                    disabledBackgroundColor: _kAccent.withOpacity(0.6),
                    disabledForegroundColor: Colors.white,
                    padding: const EdgeInsets.symmetric(
                        horizontal: 44, vertical: 14),
                    shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(6)),
                    elevation: 0,
                  ),
                  onPressed: _busy ? null : _submit,
                  child: Text(translate('Login'),
                      style: const TextStyle(
                          fontSize: 15, fontWeight: FontWeight.bold)),
                ),
              ),
              if (_busy)
                const Padding(
                  padding: EdgeInsets.only(top: 12),
                  child: LinearProgressIndicator(color: _kAccent),
                ),
              if (_error.isNotEmpty)
                Padding(
                  padding: const EdgeInsets.only(top: 16),
                  child: SelectableText(_error,
                      textAlign: TextAlign.center,
                      style: const TextStyle(fontSize: 12, color: _kError)),
                ),
              if (!widget.required)
                Padding(
                  padding: const EdgeInsets.only(top: 10),
                  child: Center(
                    child: TextButton(
                      onPressed: _busy ? null : widget.onCancel,
                      child: Text(translate('Cancel'),
                          style: const TextStyle(
                              fontSize: 13, color: Color(0xFF666677))),
                    ),
                  ),
                ),
              const _NemoCertBox(),
              Padding(
                padding: const EdgeInsets.only(top: 14),
                child: Center(
                  child: MouseRegion(
                    cursor: SystemMouseCursors.click,
                    child: GestureDetector(
                      onTap: _busy ? null : _import,
                      child: Text(
                          translate('Import setup string or device key'),
                          textAlign: TextAlign.center,
                          style: const TextStyle(
                              fontSize: 12,
                              color: _kAccent,
                              decoration: TextDecoration.underline,
                              decorationColor: _kAccent)),
                    ),
                  ),
                ),
              ),
            ],
          ),
        ));
    if (widget.required || widget.onCancel == null) return card;
    // Esc cancels an optional sign-in.
    return CallbackShortcuts(
      bindings: {
        const SingleActivator(LogicalKeyboardKey.escape): () {
          if (!_busy) widget.onCancel?.call();
        },
      },
      child: card,
    );
  }
}
