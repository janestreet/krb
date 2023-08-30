open! Core
open! Async

type t =
  { client_principal : Principal.Name.t
  ; cross_realm_client_principal : Cross_realm_principal_name.t
  ; request_forwarded_creds : unit -> Cred_cache.t Deferred.Or_error.t
  }
[@@deriving fields ~getters ~iterators:create]

let sexp_of_t
  { client_principal; cross_realm_client_principal; request_forwarded_creds = _ }
  =
  [%message
    (client_principal : Principal.Name.t)
      (cross_realm_client_principal : Cross_realm_principal_name.t)]
;;
