import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter_hbb/common/nemo_policy.dart';
import 'package:flutter_hbb/common/widgets/setting_widgets.dart';
import 'package:flutter_hbb/common/widgets/toolbar.dart';
import 'package:get/get.dart';

import '../../common.dart';
import '../../models/platform_model.dart';

void _showSuccess() {
  showToast(translate("Successful"));
}

void setTemporaryPasswordLengthDialog(
    OverlayDialogManager dialogManager) async {
  List<String> lengths = ['6', '8', '10'];
  String length = await bind.mainGetOption(key: "temporary-password-length");
  var index = lengths.indexOf(length);
  if (index < 0) index = 0;
  length = lengths[index];
  dialogManager.show((setState, close, context) {
    setLength(newValue) {
      final oldValue = length;
      if (oldValue == newValue) return;
      setState(() {
        length = newValue;
      });
      bind.mainSetOption(key: "temporary-password-length", value: newValue);
      bind.mainUpdateTemporaryPassword();
      Future.delayed(Duration(milliseconds: 200), () {
        close();
        _showSuccess();
      });
    }

    return CustomAlertDialog(
      title: Text(translate("Set one-time password length")),
      content: Row(
          mainAxisAlignment: MainAxisAlignment.spaceEvenly,
          children: lengths
              .map(
                (value) => Row(
                  children: [
                    Text(value),
                    Radio(
                        value: value, groupValue: length, onChanged: setLength),
                  ],
                ),
              )
              .toList()),
    );
  }, backDismiss: true, clickMaskDismiss: true);
}

// TBFDesk: server keys whose admin-fixed state locks the ID/Relay server dialog.
const List<String> _kNemoServerLockKeys = [
  'custom-rendezvous-server',
  'relay-server',
  'api-server',
  'key',
  kNemoCompanyNetworkOnly,
];

/// TBFDesk: any server key is pushed (fixed) by the management server.
bool nemoManagementServerSettingsLocked() =>
    _kNemoServerLockKeys.any((k) => isOptionFixed(k) == true);

/// TBFDesk: read-only notice instead of the editable server dialog.
void _nemoShowServerSettingsLocked(
    OverlayDialogManager dialogManager, String message) {
  dialogManager.show((setState, close, context) {
    return CustomAlertDialog(
      title: Text(translate('ID/Relay Server')),
      content: ConstrainedBox(
        constraints: const BoxConstraints(minWidth: 400),
        child: SelectionArea(child: Text(message)),
      ),
      actions: [dialogButton('Close', onPressed: close)],
      onSubmit: close,
      onCancel: close,
    );
  }, backDismiss: true, clickMaskDismiss: true);
}

void showServerSettings(OverlayDialogManager dialogManager,
    void Function(VoidCallback) setState) async {
  // TBFDesk: locked by the exe name (show the licence) or by management policy.
  final license = await bind.mainGetLicense();
  if (license.isNotEmpty) {
    _nemoShowServerSettingsLocked(dialogManager,
        '${translate('Server settings are locked by this executable name.')}\n$license');
    return;
  }
  if (nemoManagementServerSettingsLocked()) {
    _nemoShowServerSettingsLocked(dialogManager,
        translate('Server settings are locked by management policy.'));
    return;
  }
  Map<String, dynamic> options = {};
  try {
    options = jsonDecode(await bind.mainGetOptions());
  } catch (e) {
    print("Invalid server config: $e");
  }
  showServerSettingsWithValue(
      ServerConfig.fromOptions(options), dialogManager, setState);
}

void showServerSettingsWithValue(
    ServerConfig serverConfig,
    OverlayDialogManager dialogManager,
    void Function(VoidCallback)? upSetState) async {
  var isInProgress = false;
  final idCtrl = TextEditingController(text: serverConfig.idServer);
  final relayCtrl = TextEditingController(text: serverConfig.relayServer);
  final apiCtrl = TextEditingController(text: serverConfig.apiServer);
  final keyCtrl = TextEditingController(text: serverConfig.key);

  RxString idServerMsg = ''.obs;
  RxString relayServerMsg = ''.obs;
  RxString apiServerMsg = ''.obs;

  final controllers = [idCtrl, relayCtrl, apiCtrl, keyCtrl];
  final errMsgs = [
    idServerMsg,
    relayServerMsg,
    apiServerMsg,
  ];
  // TBFDesk: "Company network only" checkbox
  final oldCompanyOnly =
      bind.mainGetOptionSync(key: kNemoCompanyNetworkOnly) == 'Y';
  final companyOnly = oldCompanyOnly.obs;
  final companyOnlyFixed = isOptionFixed(kNemoCompanyNetworkOnly) == true;

  dialogManager.show((setState, close, context) {
    Future<bool> submit() async {
      // TBFDesk: company network only needs an ID server; keep the dialog open.
      idServerMsg.value = '';
      if (companyOnly.value && idCtrl.text.trim().isEmpty) {
        idServerMsg.value =
            translate('Company network only requires an ID server');
        return false;
      }
      setState(() {
        isInProgress = true;
      });
      bool ret = await setServerConfig(
          null,
          errMsgs,
          ServerConfig(
              idServer: idCtrl.text.trim(),
              relayServer: relayCtrl.text.trim(),
              apiServer: apiCtrl.text.trim(),
              key: keyCtrl.text.trim()));
      // TBFDesk: store the company-only flag after the server keys
      if (ret && companyOnly.value != oldCompanyOnly) {
        await bind.mainSetOption(
            key: kNemoCompanyNetworkOnly,
            value: companyOnly.value ? 'Y' : '');
      }
      setState(() {
        isInProgress = false;
      });
      return ret;
    }

    Widget buildField(
        String label, TextEditingController controller, String errorMsg,
        {String? Function(String?)? validator, bool autofocus = false}) {
      if (isDesktop || isWeb) {
        return Row(
          children: [
            SizedBox(
              width: 120,
              child: Text(label),
            ),
            SizedBox(width: 8),
            Expanded(
              child: TextFormField(
                controller: controller,
                decoration: InputDecoration(
                  errorText: errorMsg.isEmpty ? null : errorMsg,
                  contentPadding:
                      EdgeInsets.symmetric(horizontal: 8, vertical: 12),
                ),
                validator: validator,
                autofocus: autofocus,
              ).workaroundFreezeLinuxMint(),
            ),
          ],
        );
      }

      return TextFormField(
        controller: controller,
        decoration: InputDecoration(
          labelText: label,
          errorText: errorMsg.isEmpty ? null : errorMsg,
        ),
        validator: validator,
      ).workaroundFreezeLinuxMint();
    }

    return CustomAlertDialog(
      title: Row(
        children: [
          Expanded(child: Text(translate('ID/Relay Server'))),
          ...ServerConfigImportExportWidgets(controllers, errMsgs),
        ],
      ),
      content: ConstrainedBox(
        constraints: const BoxConstraints(minWidth: 500),
        child: Form(
          child: Obx(() => Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  buildField(translate('ID Server'), idCtrl, idServerMsg.value,
                      autofocus: true),
                  SizedBox(height: 8),
                  if (!isIOS && !isWeb) ...[
                    buildField(translate('Relay Server'), relayCtrl,
                        relayServerMsg.value),
                    SizedBox(height: 8),
                  ],
                  buildField(
                    translate('API Server'),
                    apiCtrl,
                    apiServerMsg.value,
                    validator: (v) {
                      if (v != null && v.isNotEmpty) {
                        if (!(v.startsWith('http://') ||
                            v.startsWith("https://"))) {
                          return translate("invalid_http");
                        }
                      }
                      return null;
                    },
                  ),
                  SizedBox(height: 8),
                  buildField('Key', keyCtrl, ''),
                  // TBFDesk: Company network only + its explanation
                  if (!isWeb) ...[
                    SizedBox(height: 8),
                    InkWell(
                      onTap: companyOnlyFixed
                          ? null
                          : () => companyOnly.value = !companyOnly.value,
                      child: Row(
                        children: [
                          Checkbox(
                            value: companyOnly.value,
                            onChanged: companyOnlyFixed
                                ? null
                                : (v) => companyOnly.value = v ?? false,
                          ),
                          SizedBox(width: 5),
                          Expanded(
                              child: Text(translate('Company network only'))),
                        ],
                      ),
                    ),
                    Text(
                      translate('nemo_company_only_tip'),
                      style: TextStyle(fontSize: 12, color: Colors.grey),
                    ),
                  ],
                  if (isInProgress)
                    Padding(
                      padding: EdgeInsets.only(top: 8),
                      child: LinearProgressIndicator(),
                    ),
                ],
              )),
        ),
      ),
      actions: [
        dialogButton('Cancel', onPressed: () {
          close();
        }, isOutline: true),
        dialogButton(
          'OK',
          onPressed: () async {
            if (await submit()) {
              close();
              showToast(translate('Successful'));
              upSetState?.call(() {});
            } else {
              showToast(translate('Failed'));
            }
          },
        ),
      ],
    );
  });
}

void setPrivacyModeDialog(
  OverlayDialogManager dialogManager,
  List<TToggleMenu> privacyModeList,
  RxString privacyModeState,
) async {
  dialogManager.dismissAll();
  dialogManager.show((setState, close, context) {
    return CustomAlertDialog(
      title: Text(translate('Privacy mode')),
      content: Column(
          mainAxisAlignment: MainAxisAlignment.spaceEvenly,
          children: privacyModeList
              .map((value) => CheckboxListTile(
                    contentPadding: EdgeInsets.zero,
                    visualDensity: VisualDensity.compact,
                    title: value.child,
                    value: value.value,
                    onChanged: value.onChanged,
                  ))
              .toList()),
    );
  }, backDismiss: true, clickMaskDismiss: true);
}
