open! Core
open! Async

type t =
  { client_principal : Principal.Name.t
  ; request_forwarded_creds : unit -> Cred_cache.t Deferred.Or_error.t
  }
[@@deriving fields]

let sexp_of_t { client_principal; request_forwarded_creds = _ } =
  [%message (client_principal : Principal.Name.t)]
;;
