open! Core.Core_stable

module Stable = struct
  module V1 = struct
    type t =
      | API
      | DIR
      | FILE
      | KEYRING
      | MEMORY
      | MSLSA
    [@@deriving bin_io, compare, enumerate, sexp]
  end
end

open! Core
include Stable.V1
include Sexpable.To_stringable (Stable.V1)
