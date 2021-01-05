open! Core
open! Async
open Import

(** Check [cred_cache] for a tgt that will still be valid after [valid_for_at_least]. *)
val check_valid
  :  ?valid_for_at_least:Time.Span.t (** default: 10m *)
  -> cred_cache:Cred_cache.t
  -> Principal.Name.t
  -> unit Deferred.Or_error.t

(** Try to initialize [cred_cache] with a tgt for [principal] if a valid one does
    not exist. Attempt to acquire a new TGT in the following ways:
    - Move a valid TGT from the default cred cache (if different from [cred_cache])
    - Get a new TGT using [keytab] (if supplied)
    - Renew an existing TGT in [cred_cache] *)
val ensure_valid
  :  ?valid_for_at_least:Time.Span.t (** default: 10m *)
  -> ?keytab:Keytab.Path.t
  -> cred_cache:Cred_cache.t
  -> Principal.Name.t
  -> unit Deferred.Or_error.t


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

(** Create a new, empty credential cache and use [keytab] and [principal] to get and
    store a tgt into the cache.

    Creating a new cred cache of types [FILE] or [DIR] leaks files on disk. The finalizer
    for [Cred_cache.t] closes the file and frees the memory associated with it, but the
    file doesn't get removed from disk. *)
val initialize_in_new_cred_cache
  :  ?cache_type:Internal.Cache_type.t (** default: MEMORY *)
  -> ?keytab:Keytab.Path.t
  -> Principal.Name.t
  -> Cred_cache.t Deferred.Or_error.t

val get_cached_tgt
  :  ?valid_for_at_least:Time.Span.t (** default: 10min *)
  -> cred_cache:Cred_cache.t
  -> Principal.Name.t
  -> Internal.Credentials.t Deferred.Or_error.t

(** Return number of active credential renewal loops, as started by calls to
    [keep_valid_indefintely]. Note that it avoids creating a new loop for credentials that
    are already being renewed, even if [keep_valid_indefinitely] is called multiple times
    on the same cred cache with the same principal + keytab. *)
val num_active_renewal_jobs : unit -> int
