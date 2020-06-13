{
  global:
        /* Not all the libcrun_ functions are exported, only those marked LIBCRUN_PUBLIC.  */
        libcrun_*;
        /* libocispec functions */
        runtime_spec_*;
        free_runtime_spec_*;
        make_runtime_spec_*;
  local: *;
};
