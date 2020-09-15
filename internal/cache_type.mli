open! Core

(** Types [API] and [MSLSA] are only supported on Windows. [KEYRING] is only supported on
    Linux *)
type t =
  | API
  | DIR
  | FILE
  | KEYRING
  | MEMORY
  | MSLSA
[@@deriving compare, enumerate, sexp_of]

include Stringable.S with type t := t

module Stable : sig
  module V1 : Stable_without_comparator with type t = t
end
