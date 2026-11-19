package eco

import "core:fmt"
import "core:os"
import "core:strings"
import "core:time"

// A dialog in the operator's session that denies by itself when the request expires.
ask_pair_approval :: proc(title, text: string) -> Pair_Answer {
    // fmt treats braces in the format string as part of an argument selector.
    buttons :: `{"Deny", "Approve"}`
    script := fmt.tprintf(`display dialog %q with title %q buttons %s default button "Deny" cancel button "Deny" with icon caution giving up after %d`,
                          text, title, buttons, int(PAIR_WAIT/time.Second))
    status, output, _, err := os.process_exec({command = {"/usr/bin/osascript", "-e", script}}, context.temp_allocator)
    if err != nil || !status.success { return .No }
    return .Yes if strings.contains(string(output), "button returned:Approve") else .No
}

close_pair_approval :: proc(title: string) {}
