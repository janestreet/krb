open! Core
open! Async
open! Import

include module type of Tgt0 (** @inline *)


(** Ensure an initial tgt. Upon success an [ensure_tgt_valid] job is scheduled to run
    every [refresh_every]. If one of these background jobs fails, the [on_error] of the
    first caller determines how to handle the error. *)
val keep_valid_indefinitely
  :  ?refresh_every:Time.Span.t (** default: 30m *)
  -> ?on_error:[ `Ignore | `Raise | `Call of Error.t -> unit ]
  (** default: call [Log.Global.error] *)
  -> ?keytab:Keytab.Path.t
  -> ?abort:unit Deferred.t
  -> cred_cache:Cred_cache.t
  -> Principal.Name.t
  -> unit Deferred.Or_error.t
