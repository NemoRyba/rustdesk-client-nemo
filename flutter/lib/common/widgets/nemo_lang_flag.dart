// TBFDesk: the three UI languages offered in Settings > General > Language, with
// drawn flags (emoji flags do not render on Windows). Mirrors the Sciter UI
// (src/ui/index.tis: svg_flag_de / svg_flag_at / svg_flag_gb, nemoLangChoices,
// nemoCurrentLang).
import 'package:flutter/material.dart';

import '../../common.dart';
import '../../consts.dart';
import '../../models/platform_model.dart';

/// One selectable UI language: the value stored in the local option `lang` and
/// the translate() key of its display name.
class NemoLangChoice {
  final String code;
  final String labelKey;
  const NemoLangChoice(this.code, this.labelKey);

  String get label => translate(labelKey);
}

/// German first (Germany, then Austria -- the same texts for now), then English.
const List<NemoLangChoice> kNemoLangChoices = [
  NemoLangChoice('de', 'nemo_lang_de'),
  NemoLangChoice('de-at', 'nemo_lang_de_at'),
  NemoLangChoice('en', 'nemo_lang_en'),
];

/// German is the default (lang.rs), so an unset / "default" option is German
/// (Germany). Any other stored value that is not one of the three choices also
/// shows as German, like the Sciter UI.
String nemoCurrentLang() {
  final v = bind.mainGetLocalOption(key: kCommConfKeyLang).toLowerCase();
  if (v.isEmpty || v == 'default') return 'de';
  for (final c in kNemoLangChoices) {
    if (c.code == v) return v;
  }
  return 'de';
}

/// A small drawn flag for [code] ('de', 'de-at' or 'en'), [width] logical pixels
/// wide; the height follows the flag's own aspect ratio.
class NemoLangFlag extends StatelessWidget {
  final String code;
  final double width;
  const NemoLangFlag({Key? key, required this.code, this.width = 21})
      : super(key: key);

  @override
  Widget build(BuildContext context) {
    final painter = _NemoFlagPainter(code);
    return SizedBox(
      width: width,
      height: width * painter.aspect,
      child: DecoratedBox(
        position: DecorationPosition.foreground,
        decoration: BoxDecoration(
          border: Border.all(color: const Color(0x33000000), width: 0.5),
        ),
        child: CustomPaint(painter: painter),
      ),
    );
  }
}

class _NemoFlagPainter extends CustomPainter {
  final String code;
  _NemoFlagPainter(this.code);

  // height / width of the flag's view box
  double get aspect {
    switch (code) {
      case 'de-at':
        return 2 / 3;
      case 'en':
        return 1 / 2;
      default:
        return 3 / 5;
    }
  }

  @override
  void paint(Canvas canvas, Size size) {
    canvas.save();
    canvas.clipRect(Offset.zero & size);
    switch (code) {
      case 'de-at':
        _paintAt(canvas, size);
        break;
      case 'en':
        _paintGb(canvas, size);
        break;
      default:
        _paintDe(canvas, size);
    }
    canvas.restore();
  }

  void _rect(Canvas canvas, double x, double y, double w, double h, int argb) {
    canvas.drawRect(Rect.fromLTWH(x, y, w, h), Paint()..color = Color(argb));
  }

  void _poly(Canvas canvas, List<double> pts, int argb) {
    final path = Path()..moveTo(pts[0], pts[1]);
    for (var i = 2; i + 1 < pts.length; i += 2) {
      path.lineTo(pts[i], pts[i + 1]);
    }
    path.close();
    canvas.drawPath(path, Paint()..color = Color(argb));
  }

  // viewBox 0 0 5 3: black / red / gold
  void _paintDe(Canvas canvas, Size size) {
    canvas.scale(size.width / 5, size.height / 3);
    _rect(canvas, 0, 0, 5, 1, 0xFF000000);
    _rect(canvas, 0, 1, 5, 1, 0xFFDD0000);
    _rect(canvas, 0, 2, 5, 1, 0xFFFFCE00);
  }

  // viewBox 0 0 3 2: red / white / red
  void _paintAt(Canvas canvas, Size size) {
    canvas.scale(size.width / 3, size.height / 2);
    _rect(canvas, 0, 0, 3, 2, 0xFFED2939);
    _rect(canvas, 0, 2 / 3, 3, 2 / 3, 0xFFFFFFFF);
  }

  // viewBox 0 0 60 30: simplified Union Flag (same shapes as the Sciter SVG)
  void _paintGb(Canvas canvas, Size size) {
    canvas.scale(size.width / 60, size.height / 30);
    _rect(canvas, 0, 0, 60, 30, 0xFF012169);
    _poly(canvas, [0, 0, 7, 0, 60, 26.5, 60, 30, 53, 30, 0, 3.5], 0xFFFFFFFF);
    _poly(canvas, [60, 0, 53, 0, 0, 26.5, 0, 30, 7, 30, 60, 3.5], 0xFFFFFFFF);
    _poly(canvas, [0, 0, 2.5, 0, 60, 28.75, 60, 30, 57.5, 30, 0, 1.25],
        0xFFC8102E);
    _poly(canvas, [60, 0, 57.5, 0, 0, 28.75, 0, 30, 2.5, 30, 60, 1.25],
        0xFFC8102E);
    _rect(canvas, 25, 0, 10, 30, 0xFFFFFFFF);
    _rect(canvas, 0, 10, 60, 10, 0xFFFFFFFF);
    _rect(canvas, 27, 0, 6, 30, 0xFFC8102E);
    _rect(canvas, 0, 12, 60, 6, 0xFFC8102E);
  }

  @override
  bool shouldRepaint(covariant _NemoFlagPainter oldDelegate) =>
      oldDelegate.code != code;
}
