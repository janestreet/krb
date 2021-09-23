open! Core
open! Async
open! Import
open Deferred.Or_error.Let_syntax
include Tgt0

let keep_valid_indefinitely ?refresh_every ?on_error ?keytab ?abort ~cred_cache principal =
  let%bind () =
    match Internal.Cred_cache.type_ cred_cache with
    | `Normal -> return ()
    | `S4U2Self _ ->
      Deferred.Or_error.error_s
        [%message
          "can't keep the TGT valid in a TGT-less cache"
            ~cred_cache:(Internal.Cred_cache.Expert.full_name cred_cache : string)]
  in
  Principal.Name.with_default_realm principal
  >>= Keep_valid.f ?refresh_every ?on_error ?keytab ?abort ~cred_cache
;;
