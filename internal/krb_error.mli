open! Core
open! Async

type t = Krb_error0.t [@@deriving sexp_of]

(** [to_string ?context ~info code] looks up the description of [code] in the kerberos
    error tables and appends that to [info], which should likely be the name of the c
    function that returned [code]. *)
val to_string : ?context:Context.t -> info:string -> t -> string
