open! Core
open! Async
open! Import

include module type of Cred_cache0 (** @inline *)

(** Return number of active credential renewal loops, as started by calls to
    [keep_valid_indefintely]. Note that it avoids creating a new loop for credentials that
    are already being renewed, even if [keep_valid_indefinitely] is called multiple times
    on the same cred cache with the same principal + keytab. *)
val num_active_renewal_jobs : unit -> int

(** If this cred cache is expected to contain a TGT, keep that TGT valid. If it is a
    S4U2Self cache, keep the expected ticket valid.

    A [keytab] should only be provided for TGT caches. It defaults to the [User] keytab if
    none is provided.

    A [server_cred_cache] should only be provided if [t] is a S4U2Self cache. The default
    cred cache is used if none is provided. *)
val keep_valid
  :  ?refresh_every:Time.Span.t (** default: 30m *)
  -> ?on_error:[ `Ignore | `Raise | `Call of Error.t -> unit ]
  (** default: call [Log.Global.error] *)
  -> ?keytab:Keytab.Path.t
  -> ?server_cred_cache:t
  -> ?abort:unit Deferred.t
  -> t
  -> unit Deferred.Or_error.t
