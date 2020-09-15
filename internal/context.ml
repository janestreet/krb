open! Core

type t

external init : unit -> (t, Krb_error0.t) Result.t = "caml_krb5_init_context_global"
