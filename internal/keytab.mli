open! Core
open Async

(** See ../src/keytab.mli for more documentation *)

(** [krb5_keytab] *)
type t [@@deriving sexp_of]

val path : t -> string
val load : string -> t Deferred.Or_error.t
val add_entry : t -> Keytab_entry.t -> unit Deferred.Or_error.t
val remove_entry : t -> Keytab_entry.t -> unit Deferred.Or_error.t
val entries : t -> Keytab_entry.t list Deferred.Or_error.t

module Raw : sig
  type t
end

val to_raw : t -> Raw.t
