The C source code under the directory src/ follows this convention regarding error handling:

Functions that can return a failure to the caller, take the argument
`libcrun_error_t *err` and return either an int or a pointer.

If the function succeeds, then

- `0` or a non-NULL pointer is returned.
- _err_ is not altered.

If the function fails, then

- a negative number or a non-NULL pointer is returned.
- _err_ is set to the pointer of an allocated struct libcrun_error_s.
   The member _status_ is to an errno-style value.
   The member _msg_ is set to an allocated error message string.

The functions expect that the passed in _err_ is not pointing to an already created libcrun_error_s.

Exceptions to the above convention are:
(TODO write something here)
