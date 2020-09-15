open! Core

(** [krb5_data].

    Generic kerberos type that stores arbitrary "data" (e.g. password salts, tickets,
    etc.) *)
type t

val free : Context.t -> t -> unit
