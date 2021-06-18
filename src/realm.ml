open! Core
open Async
open Import

type t = string [@@deriving bin_io, compare, hash, sexp]

let test_realm = "TEST.REALM.COM"

(* In [Krb.Mode.Test_with_principal], we may not have a kerberos
   environment available and can't query for the actual default
   realm. *)
let default () =
  if am_running_test && not Config.am_sandboxed
  then Deferred.Or_error.return test_realm
  else Internal.Principal.default_realm ()
;;
