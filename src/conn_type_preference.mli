open! Core

(** A collection of supported [Conn_type.t] in (optional) order of preference.

    The following algorithm is used when negotiating connection types:

    [Any a1]/[Any a2] => Strongest connection type in both [a1] and [a2]

    [Any a]/[Prefer p] => First connection type in [p] that is in [a]

    [Prefer p1]/[Prefer p2] => Let [p1'] be the filtered list [p1] with only elements that
    are members of [p2]. Let [p2'] be the equivalent filtered list [p2]. If the head of
    [p1'] and [p2'] are the same, use that connection type. Otherwise, use the strongest
    connection in both [p1'] and [p2']
*)

type t =
  | Prefer of Conn_type.t list
  | Any of Conn_type.Set.t
[@@deriving compare, hash, sexp_of]

val accept_only : Conn_type.t -> t

(** [accept_all] and [accept_safe_priv] express no preference *)
val accept_all : t

val accept_safe_priv : t

(** [prefer_speed] and [prefer_strength] allow all connection types but express a
    preference *)
val prefer_speed : t

val prefer_strength : t
val to_set : t -> Conn_type.Set.t
val filter : t -> only_in:t -> t
val negotiate : us:t -> peer:t -> Conn_type.t Or_error.t
val flag : t Command.Param.t
val optional_flag : t option Command.Param.t

module Stable : sig
  open Core.Core_stable

  module V1 : sig
    type nonrec t = t =
      | Prefer of Conn_type.Stable.V1.t list
      | Any of Conn_type.Stable.V1.Set.t

    type nonrec comparator_witness

    include Stable with type t := t with type comparator_witness := comparator_witness

    include
      Comparable.V1.S
      with type comparable := t
      with type comparator_witness := comparator_witness
  end
end
