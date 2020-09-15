module Stable = struct
  open Core.Core_stable
  module Log_output = Env_config.Log_output.Stable.V1

  module V1 = struct
    type t = Log_output.t list [@@deriving sexp]
  end
end

open! Core
open Env_config
include Stable.V1

let examples =
  [ [ Log_output.Stderr ]
  ; [ Log_output.File { format = `Sexp; filename = "krb_debug.log" } ]
  ]
;;
