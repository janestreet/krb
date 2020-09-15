module Stable = struct
  open! Core.Core_stable
  module Keytab = Keytab.Stable
  module Principal = Principal.Stable

  module V2 = struct
    type t =
      | Tgt
      | Keytab of Principal.Name.V1.t * Keytab.Path.V1.t
    [@@deriving bin_io, compare, sexp]
  end
end

open! Core
open! Async
open Import

type t = Stable.V2.t =
  | Tgt
  | Keytab of Principal.Name.t * Keytab.Path.t
[@@deriving compare, hash, sexp_of]

let best_effort_validate ?refresh_tgt ~cred_cache t =
  match t with
  | Tgt ->
    Cred_cache.principal cred_cache
    >>=? fun principal_name -> Tgt.check_valid ~cred_cache principal_name
  | Keytab (principal_name, keytab_path) ->
    (match refresh_tgt with
     | None -> Keytab.validate_path keytab_path principal_name
     | Some () ->
       Tgt.keep_valid_indefinitely ~cred_cache ~keytab:keytab_path principal_name)
;;

let principal t =
  let open Deferred.Or_error.Let_syntax in
  match t with
  | Tgt ->
    let%bind cred_cache = Cred_cache.default () in
    Internal.Cred_cache.principal cred_cache
  | Keytab (principal_name, _) -> Principal.create principal_name
;;
