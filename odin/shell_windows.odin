package eco

// Git Bash reads its command line through the MSYS2 runtime, which expands wildcards, splits
// unquoted words at line breaks and truncates quoted words longer than its glob buffer. The script
// and its parameters travel as `_` and `\xHH`-escaped bytes that the runtime keeps verbatim, and
// this prelude decodes them before it runs the script with its parameters.
SHELL_DECODE :: `for _eco; do printf -v _eco %b "${_eco#_}"; set -- "$@" "$_eco"; shift; done; ` +
                `unset _eco; eval "shift; $1"`

shell_arguments :: proc(args: []cstring, shell: cstring, words: []cstring) -> (storage: []byte, ok: bool) {
    size := 0
    for word in words { size += 2 + 4*len(word) }
    buffer, err := make([]byte, size)
    if err != nil { return nil, false }
    storage = buffer
    digits := "0123456789abcdef"
    args[0], args[1], args[2], args[3] = shell, "-c", SHELL_DECODE, "sh"
    n := 0
    for word, i in words {
        args[4+i] = cstring(&storage[n])
        storage[n] = '_'
        n += 1
        for b in transmute([]byte)string(word) {
            switch b {
            case 'a'..='z', 'A'..='Z', '0'..='9', '_', '-', '.', ',', '/', ':', '=', '+':
                storage[n] = b
                n += 1
            case:
                storage[n], storage[n+1] = '\\', 'x'
                storage[n+2], storage[n+3] = digits[b >> 4], digits[b & 15]
                n += 4
            }
        }
        storage[n] = 0
        n += 1
    }
    return storage, true
}
