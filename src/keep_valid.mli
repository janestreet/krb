(** This module is not exposed in the library interface, and thus not well-docced. See the
    public versions of these functions in [Cred_cache] for documentation. *)

open! Core
open! Async
open! Import

val num_active_renewal_jobs : unit -> int

val f
  :  ?refresh_every:Time.Span.t
  -> ?on_error:[ `Call of Error.t -> unit | `Ignore | `Raise ]
  -> ?keytab:Keytab.Path.t
  -> ?server_cred_cache:Cred_cache0.t
  -> ?abort:unit Deferred.t
  -> cred_cache:Cred_cache0.t
  -> Cross_realm_principal_name.t
  -> unit Deferred.Or_error.t
