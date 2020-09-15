open! Core
open Async

(** [krb5_keytab_entry]

    A keytab entry consists of
    - a principal -- the identity of an actor we want to authenticate
    - a keyblock -- encryption keys derived from the principal's password
    - a key version number (kvno) -- a sequence number indicating which of the
      principal's historical passwords the keyblock was derived from.

    You can think of a keytab as the set of identities one may take on as the holder of a
    particular password.
*)
type t

val create : Principal.t -> kvno:int -> Keyblock.t -> t Deferred.Or_error.t

(** [principal] and [keyblock] return copies of underlying kerberos structures. *)
val principal : t -> Principal.t Deferred.Or_error.t

val keyblock : t -> Keyblock.t Deferred.Or_error.t
val kvno : t -> int

module Raw : sig
  val free : Context.t -> t -> unit
end
