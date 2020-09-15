open! Core

type t = Krb_error0.t [@@deriving sexp_of]

external to_string : Context.t option -> t -> string = "caml_krb5_get_error_message"

let to_string ?context ~info code = sprintf "%s: %s" info (to_string context code)
