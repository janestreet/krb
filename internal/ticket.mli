open! Core

(** [krb5_ticket]

    Kerberos ticket structure.

    See credentials.mli for more information.
*)
type t

val decode : Data.t -> t Or_error.t
val kvno : t -> int
val enctype : t -> Enctype.t Or_error.t
