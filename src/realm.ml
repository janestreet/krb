open! Core
open Async
open Import

type t = string [@@deriving bin_io, compare, hash, sexp]

let test_realm = "TEST.REALM.COM"

(* In [Krb.Mode.Test_with_principal], we may not have a kerberos
   environment available and can't query for the actual default
   realm.

   However, if we are expecting to reach out to an actual KDC (either
   ambient or within a sandbox), we should have a kerberos environment
   available. *)
let expecting_kdc_available = Config.am_sandboxed || Config.am_exempt_from_sandbox

let default () =
  if am_running_test && not expecting_kdc_available
  then Deferred.Or_error.return test_realm
  else Internal.Principal.default_realm ()
;;
