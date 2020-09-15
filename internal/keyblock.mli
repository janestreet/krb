open! Core
open Async

(** [krb5_keyblock]

    An encryption type together with some key for that encryption type. *)
type t

include Comparable.S_plain with type t := t

(** Derive a keyblock from (1) the principal's password and (2) a salt value to make it
    likely that even principals with the same password end up with different encryption
    keys. *)
val create : Enctype.t -> password:string -> salt:Data.t -> t Deferred.Or_error.t

(** Create a keyblock from raw key data. *)
val create_from_key_data : enctype:Enctype.t -> Bigstring.t -> t Deferred.Or_error.t

val enctype : t -> Enctype.t
val key : t -> string

val decrypt
  :  t
  -> usage:Key_usage_number.t
  -> enctype:Enctype.t
  -> kvno:int
  -> Bigsubstring.t
  -> Bigstring.t Deferred.Or_error.t

module Raw : sig
  val free : Context.t -> t -> unit
end
