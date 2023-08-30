open! Core
open! Async
open! Import

(** See [principal.mli] for additional documentation.

    This type represents a principal name much like [Principal.Name.t] with the additional
    property that it carries realm information rather than assuming the default realm. In
    addition, the hostname in [Service.t] should be fully qualified as it does not assume
    the default domain. See [Fqdn] for domain-related utility functions.
*)
module User : sig
  type t =
    { username : string
    ; realm : Realm.t
    }
  [@@deriving sexp_of]

  val with_default_realm : string -> t Deferred.Or_error.t
end

module Service : sig
  type t =
    { service : string
    ; hostname : string
    ; realm : Realm.t
    }
  [@@deriving sexp_of]

  val with_default_realm : service:string -> hostname:string -> t Deferred.Or_error.t
end

type t =
  | User of User.t
  | Service of Service.t
[@@deriving sexp_of]

include Comparable.S_plain with type t := t
include Hashable.S_plain with type t := t

val to_string : t -> string

(** [of_string] returns an error if the supplied principal string doesn't have a realm. *)
val of_string : string -> t Or_error.t

val of_string_exn : string -> t
val realm : t -> Realm.t

module Stable : sig
  module V1 : sig
    type nonrec t = t [@@deriving bin_io, compare, sexp]

    include
      Comparable.Stable.V1.S
        with type comparable := t
        with type comparator_witness := comparator_witness
  end
end
