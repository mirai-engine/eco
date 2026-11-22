#+build !windows
package eco

// Runs `SHELL -c SCRIPT sh PARAMETER...`.
shell_arguments :: proc(args: []cstring, shell: cstring, words: []cstring) -> (storage: []byte, ok: bool) {
    args[0], args[1], args[2], args[3] = shell, "-c", words[0], "sh"
    copy(args[4:], words[1:])
    return nil, true
}
