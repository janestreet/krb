open! Core

let default =
  { Config_gen.pre_v5_assumed_realm = None
  ; host_keytab_path = None
  ; user_keytab_dir_template = None
  ; default_domain = None
  ; debug_log_config = None
  ; verbose_errors = None
  ; am_sandboxed = None
  }
;;

let help_message ~default ~environment_variable ~field_descriptions =
  String.concat
    [ "The "
    ; environment_variable
    ; " environment variable affects the Krb\n\
       library in various ways.  Its value should be a sexp of the following form,\n\
       where all fields are required:\n\n"
    ; Sexp.to_string_hum (Config_gen.sexp_of_t default)
    ; "\n\nHere is an explanation of each field.\n"
    ; field_descriptions
    ]
;;

include (val Config_gen.make ~default ~help_message)
