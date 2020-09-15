open! Core

(*_ [Krb_error0] breaks a cyclic dependency between [Krb_error.to_string] which takes an
  optional [Context.t] and [Context.init] which returns a [Krb_error.t]. *)

type t = int32 [@@deriving sexp_of]
