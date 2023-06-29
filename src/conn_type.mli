open! Core

(** Levels of Kerberos protection on the connection, in order of increasing strength:

    {ul
    {li [Auth]: The client is authenticated to the server, but all information is sent in
    plaintext afterward}

    {li [Safe]: The client is authenticated. Afterward all information is sent in plaintext
    but contains a checksum to check for integrity.}

    {li [Priv]: The client is authenticated, and all communication is encrypted.}
    }

    The client and server each communicate a set of levels they will accept and settle on
    using the strongest one acceptable to both sides.
*)
type t =
  | Auth
  | Safe
  | Priv
[@@deriving compare, enumerate, hash, sexp_of]

include Comparable.S_plain with type t := t
include Stringable.S with type t := t

val strongest : Set.t -> t option

(** Find the strongest connection type supported by [us] and [peer], if any *)
val negotiate_strongest : us:Set.t -> peer:Set.t -> t Or_error.t

val is_as_strong : t -> as_:t -> bool

module Stable : sig
  module V1 : sig
    type nonrec t = t =
      | Auth
      | Safe
      | Priv
    [@@deriving bin_io, compare, sexp]

    type nonrec comparator_witness = comparator_witness

    include
      Comparable.Stable.V1.S
      with type comparable := t
      with type comparator_witness := comparator_witness
  end
end

module Deprecated : sig
  val flag : t list Command.Param.t
  val optional_flag : t list option Command.Param.t
end
