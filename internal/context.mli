open! Core

(** [krb5_context]

    A global kerberos context that holds all per thread state (e.g. global variables). We
    do all our work with one thread, thus one context. *)
type t

(** This call is idempotent and multiple calls will return the same context. *)
val init : unit -> (t, Krb_error0.t) Result.t
