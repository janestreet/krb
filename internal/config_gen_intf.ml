
(** Hardcoded constants that affect the behavior of the Krb library.

    These can be changed by setting an environment variable, [OCAML_KRB_CONFIG], to a sexp
    representation of the config. Also, setting [OCAML_KRB_CONFIG] to an invalid sexp
    (e.g. the empty string), will cause your program to print to stderr a usage message
    describing how to configure [OCAML_KRB_CONFIG], and exit nonzero. For example, the
    following shell command should print the usage message:

    {v
      OCAML_KRB_CONFIG= foo.exe
    v} *)

open! Core

module type S = sig
  type t =
    { pre_v5_assumed_realm : string option
    ; host_keytab_path : string option
    ; user_keytab_dir_template : string option
    ; default_domain : string option option
    ; debug_log_config : Debug_log_config.t option
    ; verbose_errors : bool option
    ; sandboxing_state : [ `None | `Sandboxed | `Exempted ] option
    }
  [@@deriving sexp_of]

  val username_template : string
  val environment_variable : string
  val t : t
  val pre_v5_assumed_realm : string
  val host_keytab_path : string
  val user_keytab_dir_template : string
  val user_keytab_dir : username:string -> string
  val default_domain : string option
  val debug_log_config : Debug_log_config.t
  val verbose_errors : bool
  val am_sandboxed : bool
  val am_exempt_from_sandbox : bool

  (** [true] iff [List.length debug_log_config > 0] *)
  val print_debug_messages : bool
end

module type Config_gen = sig
  type t =
    { pre_v5_assumed_realm : string option
    ; host_keytab_path : string option
    ; user_keytab_dir_template : string option
    ; default_domain : string option option
    ; debug_log_config : Debug_log_config.t option
    ; verbose_errors : bool option
    ; sandboxing_state : [ `None | `Sandboxed | `Exempted ] option
    }
  [@@deriving sexp_of]

  val environment_variable : string
  val username_template : string

  module type S = S with type t = t

  val make
    :  default:t
    -> help_message:
         (default:t -> environment_variable:string -> field_descriptions:string -> string)
    -> (module S)
end
