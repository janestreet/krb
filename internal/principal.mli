open! Core
open Async

(** See ../src/principal.mli for more documentation *)

(** [krb5_principal] *)
type t [@@deriving sexp_of]

val of_string : string -> t Deferred.Or_error.t
val to_string : t -> string
val realm : t -> string
val salt : t -> Data.t Deferred.Or_error.t
val default_realm : unit -> string Deferred.Or_error.t

module Raw : sig
  type t

  val free : Context.t -> t -> unit

  (** A credential cache can store arbitrary configuration for a particular principal.
      These are stored alongside normal credentials, but we don't want to show these in a
      credential cache listing. [is_config_principal] can be called to determine if the
      principal for some credentials is normal or part of a stored configuration. *)
  val is_config_principal : Context.t -> t -> bool
end

val to_raw : t -> Raw.t
val of_raw : Raw.t -> t Deferred.Or_error.t
