open! Core
open Env_config

type t = Log_output.t list [@@deriving sexp_of]

val examples : t list

module Stable : sig
  module V1 : sig
    type nonrec t = t [@@deriving sexp]
  end
end
