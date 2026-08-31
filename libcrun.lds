LIBCRUN_1.0 {
  global:
        /* Error handling.  */
        libcrun_error_get_status;
        libcrun_error_get_message;
        libcrun_error_release;
        libcrun_make_error;
        libcrun_error_report_and_release;
        libcrun_fail_with_error;

        /* Logging.  */
        libcrun_set_verbosity;
        libcrun_get_verbosity;
        libcrun_set_log_format;
        libcrun_debug;
        libcrun_warning;
        libcrun_error;
        libcrun_context_init_logging;

        /* Context.  */
        libcrun_context_new;
        libcrun_context_free;
        libcrun_context_set_id;
        libcrun_context_set_state_root;
        libcrun_context_set_bundle;
        libcrun_context_set_console_socket;
        libcrun_context_set_pid_file;
        libcrun_context_set_notify_socket;
        libcrun_context_set_handler;
        libcrun_context_set_preserve_fds;
        libcrun_context_get_preserve_fds;
        libcrun_context_set_listen_fds;
        libcrun_context_set_args;
        libcrun_context_set_systemd_cgroup;
        libcrun_context_set_detach;
        libcrun_context_set_no_new_keyring;
        libcrun_context_set_no_pivot;
        libcrun_context_set_force_no_cgroup;
        libcrun_context_set_output_handler;

        /* Container object.  */
        libcrun_container_load_from_file;
        libcrun_container_load_from_memory;
        libcrun_container_free;
        libcrun_container_get_config_json;
        libcrun_container_get_annotation;
        libcrun_container_get_uid;
        libcrun_container_get_gid;

        /* Lifecycle.  */
        libcrun_container_run;
        libcrun_container_create;
        libcrun_container_start;
        libcrun_container_delete;
        libcrun_container_kill;
        libcrun_container_killall;
        libcrun_container_pause;
        libcrun_container_unpause;
        libcrun_container_update;

        /* JSON in, JSON out.  */
        libcrun_container_spec_json;
        libcrun_container_state_json;
        libcrun_container_get_features_json;

        /* Exec.  */
        libcrun_container_exec_json;
        libcrun_container_exec_with_options_json;

        /* Status.  */
        libcrun_container_status_load;
        libcrun_container_status_free;
        libcrun_status_get_state;
        libcrun_status_get_pid;
        libcrun_status_get_bundle;
        libcrun_status_get_rootfs;
        libcrun_status_get_created;
        libcrun_status_get_owner;
        libcrun_status_get_external_descriptors;
        libcrun_container_get_state_string;
        libcrun_get_state_dir;

        /* List containers.  */
        libcrun_container_list;
        libcrun_container_list_json;
        libcrun_container_list_iter;
        libcrun_container_iter_next;
        libcrun_container_iter_free;
        libcrun_container_list_free;

        /* Update resources and mounts.  */
        libcrun_container_update_from_file;
        libcrun_container_update_from_values;
        libcrun_container_update_intel_rdt;
        libcrun_container_add_mounts_from_file;
        libcrun_container_remove_mounts_from_file;

        /* Processes.  */
        libcrun_container_read_pids;

        /* Checkpoint / restore.  */
        libcrun_container_checkpoint;
        libcrun_container_restore;

        /* Handlers.  */
        libcrun_context_get_handler_feature_tags;

  local: *;
};
