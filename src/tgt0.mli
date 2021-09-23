open! Core
open! Async
open Import

(** Check [cred_cache] for a tgt that will still be valid after [valid_for_at_least]. *)
val check_valid
  :  ?valid_for_at_least:Time.Span.t (** default: 10m *)
  -> cred_cache:Cred_cache0.t
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
  -> cred_cache:Cred_cache0.t
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
  -> Cred_cache0.t Deferred.Or_error.t

val get_cached_tgt
  :  ?valid_for_at_least:Time.Span.t (** default: 10min *)
  -> cred_cache:Cred_cache0.t
  -> Principal.Name.t
  -> Internal.Credentials.t Deferred.Or_error.t

module Cross_realm : sig
  val ensure_valid
    :  ?valid_for_at_least:Time.Span.t (** default: 10m *)
    -> ?keytab:Keytab.Path.t
    -> cred_cache:Cred_cache0.t
    -> Cross_realm_principal_name.t
    -> unit Deferred.Or_error.t
end
