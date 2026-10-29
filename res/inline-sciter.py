#!/usr/bin/env python3

import re


# Always UTF-8. Python's open() otherwise uses the platform code page -- cp1252 on
# Windows -- which turned every non-ASCII literal in the .tis/.html ("…", "▾", em
# dashes) into mojibake ("â€¦") when inline.rs was generated on the Windows build host.
def _rd(path): return open(path, encoding='utf-8').read()

def strip(s): return re.sub(r'\s+\n', '\n', re.sub(r'\n\s+', '\n', s))

common_css = _rd('src/ui/common.css')
common_tis = _rd('src/ui/common.tis')

index = _rd('src/ui/index.html') \
    .replace('@import url(index.css);', _rd('src/ui/index.css')) \
    .replace('include "index.tis";', _rd('src/ui/index.tis')) \
    .replace('include "msgbox.tis";', _rd('src/ui/msgbox.tis')) \
    .replace('include "ab.tis";', _rd('src/ui/ab.tis'))

remote = _rd('src/ui/remote.html') \
    .replace('@import url(remote.css);', _rd('src/ui/remote.css')) \
    .replace('@import url(header.css);', _rd('src/ui/header.css')) \
    .replace('@import url(file_transfer.css);', _rd('src/ui/file_transfer.css')) \
    .replace('include "remote.tis";', _rd('src/ui/remote.tis')) \
    .replace('include "msgbox.tis";', _rd('src/ui/msgbox.tis')) \
    .replace('include "grid.tis";', _rd('src/ui/grid.tis')) \
    .replace('include "header.tis";', _rd('src/ui/header.tis')) \
    .replace('include "file_transfer.tis";', _rd('src/ui/file_transfer.tis')) \
    .replace('include "port_forward.tis";', _rd('src/ui/port_forward.tis')) \
    .replace('include "printer.tis";', _rd('src/ui/printer.tis'))

chatbox = _rd('src/ui/chatbox.html')
install = _rd('src/ui/install.html').replace('include "install.tis";', _rd('src/ui/install.tis'))
update = _rd('src/ui/update.html')

cm = _rd('src/ui/cm.html') \
    .replace('@import url(cm.css);', _rd('src/ui/cm.css')) \
    .replace('include "cm.tis";', _rd('src/ui/cm.tis'))


def compress(s):
    s = s.replace("\r\n", "\n")
    x = bytes(s, encoding='utf-8')
    return '&[u8; ' + str(len(x)) + '] = b"' + str(x)[2:-1].replace(r"\'", "'").replace(r'"',
                                                                                  r'\"') + '"'


with open('src/ui/inline.rs', 'wt') as fh:
    fh.write('const _COMMON_CSS: ' + compress(strip(common_css)) + ';\n')
    fh.write('const _COMMON_TIS: ' + compress(strip(common_tis)) + ';\n')
    fh.write('const _INDEX: ' + compress(strip(index)) + ';\n')
    fh.write('const _REMOTE: ' + compress(strip(remote)) + ';\n')
    fh.write('const _CHATBOX: ' + compress(strip(chatbox)) + ';\n')
    fh.write('const _INSTALL: ' + compress(strip(install)) + ';\n')
    fh.write('const _UPDATE: ' + compress(strip(update)) + ';\n')
    fh.write('const _CONNECTION_MANAGER: ' + compress(strip(cm)) + ';\n')
    fh.write('''
fn get(data: &[u8]) -> String {
    String::from_utf8_lossy(data).to_string()
}
fn replace(data: &[u8]) -> String {
    let css = get(&_COMMON_CSS[..]);
    let res = get(data).replace("@import url(common.css);", &css);
    let tis = get(&_COMMON_TIS[..]);
    res.replace("include \\\"common.tis\\\";", &tis)
}
#[inline]
pub fn get_index() -> String {
    replace(&_INDEX[..])
}
#[inline]
pub fn get_remote() -> String {
    replace(&_REMOTE[..])
}
#[inline]
pub fn get_install() -> String {
    replace(&_INSTALL[..])
}
#[inline]
pub fn get_update() -> String {
    replace(&_UPDATE[..])
}
#[inline]
pub fn get_chatbox() -> String {
    replace(&_CHATBOX[..])
}
#[inline]
pub fn get_cm() -> String {
    replace(&_CONNECTION_MANAGER[..])
}
''')
