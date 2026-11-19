package eco

import win32 "core:sys/windows"

// A topmost Yes/No dialog in the operator's session. No is the default, so a stray Enter denies.
ask_pair_approval :: proc(title, text: string) -> Pair_Answer {
    style: win32.UINT = win32.MB_YESNO | win32.MB_ICONQUESTION | win32.MB_DEFBUTTON2 | win32.MB_SETFOREGROUND | win32.MB_TOPMOST
    result := win32.MessageBoxW(nil, win32.utf8_to_wstring(text), win32.utf8_to_wstring(title), style)
    return .Yes if result == win32.IDYES else .No
}

// A Yes/No dialog has no close button, so an expired request presses No.
close_pair_approval :: proc(title: string) {
    if window := win32.FindWindowW(nil, win32.utf8_to_wstring(title)); window != nil {
        _ = win32.PostMessageW(window, win32.WM_COMMAND, win32.IDNO, 0)
    }
}
