The C source code under the directory `src/` follows this convention regarding error handling:

Functions that can return a failure to the caller, take the argument
`libcrun_error_t *err` and return an int or a pointer.

If the function succeeds, then

- `0` or a non-NULL pointer is returned.
- `err` is not modified.

If the function fails, then

- a negative number or a non-NULL pointer is returned.
- `err` is set to the pointer of an allocated `struct libcrun_error_s`.
   The member `status` is set to an errno-style value.
   The member `msg` is set to an allocated error message string.
