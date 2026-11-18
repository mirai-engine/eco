package eco

import "core:c"

foreign import platform "../.eco-deps/eco_platform.lib"

foreign platform {
    eco_default_pipe :: proc "c" (buffer: rawptr, capacity: c.int) -> c.int ---
    eco_make_private :: proc "c" (name: cstring, buffer: rawptr, length: c.int) -> c.int ---
}

default_pipe_name :: proc() -> string {
    buffer := make([]byte, 200, context.temp_allocator)
    n := eco_default_pipe(raw_data(buffer), c.int(len(buffer)))
    return string(buffer[:n]) if n > 0 else ""
}
