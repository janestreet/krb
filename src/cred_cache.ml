open! Core
open! Async
open! Import
open Deferred.Or_error.Let_syntax
include Cred_cache0

let keep_valid ?refresh_every ?on_error ?keytab ?server_cred_cache ?abort t =
  let%bind principal = Cross_realm.principal t in
  Keep_valid.f
    ?refresh_every
    ?on_error
    ?keytab
    ?server_cred_cache
    ?abort
    ~cred_cache:t
    principal
;;

let num_active_renewal_jobs = Keep_valid.num_active_renewal_jobs
