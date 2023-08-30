open! Core

(** A collection of supported [Conn_type.t] in (optional) order of preference. [accept_*]
    constructions express no preference, while [prefer_*] do.

    When neither side expresses a preference, the connection uses the strongest conn-type
    that is supported by both.

    When one side expresses a preference, the connection uses the most-preferred conn-type
    that is accepted by the other side.

    When both sides express a preference, the preference lists are each filtered to only
    those that appear in the other. If, after that, both lists have the same first
    element, that conn-type is used. Otherwise, use the strongest conn-type that is
    acceptable to both. *)

type t [@@deriving compare, hash, sexp_of]

val accept_only : Conn_type.t -> t

(** [accept_all] and [accept_safe_priv] express no preference *)
val accept_all : t

val accept_safe_priv : t

(** [prefer_speed] and [prefer_strength] allow all connection types but express a
    preference *)
val prefer_speed : t

val prefer_strength : t

(** This is a specific value used by a single caller. You probably don't need it. *)
val prefer_speed_no_auth : t

val to_set : t -> Conn_type.Set.t
val filter : t -> only_in:t -> t
val negotiate : us:t -> peer:t -> Conn_type.t Or_error.t

(** This can be useful to decide whether a [Krb.Mode.*.t] can be cleanly converted to the
    appropriate [Krb.Mode.*_with_auth_conn_type.t]. *)
val allows_non_auth : t -> bool

module Stable : sig
  open Core.Core_stable

  module V1 : sig
    type nonrec t = t
    type nonrec comparator_witness

    include Stable with type t := t with type comparator_witness := comparator_witness

    include
      Comparable.V1.S
        with type comparable := t
        with type comparator_witness := comparator_witness
  end
end

module Deprecated : sig
  val flag : t Command.Param.t
  val optional_flag : t option Command.Param.t
  val to_flag_args : Stable.V1.t -> string list
end
