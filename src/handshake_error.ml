open Core
open Async
open! Import

module Kind = struct
  type t =
    | Incompatible_client
    | Unexpected_or_no_client_bytes
    | Unexpected_exception
  [@@deriving sexp]
end

type t = Kind.t * Error.t [@@deriving sexp]

let of_error ~kind error = kind, error
let of_result ~kind r = Deferred.Result.map_error r ~f:(of_error ~kind)

let ignore_handshake_error_kind = function
  | `Ignore -> `Ignore
  | `Raise -> `Raise
  | `Call f -> `Call (fun _ addr exn -> f addr exn)
;;
