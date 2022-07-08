open! Core
open Async

(** [krb5_ccache]

    A cache of credentials. This includes service tickets and ticket granting tickets
    (TGT).

    It uses a custom hash function such that [compare t1 t2] = 0 => [hash t1] = [hash t2]
*)
type t [@@deriving compare, hash, sexp_of]

val hash : t -> int

(** the credentials cache indicated by the environment variable KRB5CCNAME *)
val default : unit -> t Deferred.Or_error.t

(** [`Normal] cred caches should have a TGT, in addition to potentially other tickets. In
    other cases (such as the result of an S4U2Self-based cache) the cred cache may not be
    expected to have a TGT. By tagging caches with this extra information, we can have
    more reasonable behavior in instances of trying to renew a cache and the like. *)
val type_ : t -> [ `Normal | `S4U2Self of Principal.t ]

val initialize : t -> Principal.t -> unit Deferred.Or_error.t

(** Creating a cred cache of types [FILE] or [DIR] (and possibly others) leaks files on
    disk. The finalizer for [Cred_cache.t] closes the file and frees the memory associated
    with it, but the file doesn't get removed from disk. *)
val create
  :  ?type_:[ `Normal | `S4U2Self of Principal.t ] (** Defaults to [`Normal] *)
  -> Cache_type.t
  -> Principal.t
  -> t Deferred.Or_error.t

val principal : t -> Principal.t Deferred.Or_error.t
val store : t -> Credentials.t -> unit Deferred.Or_error.t

(** [initialize] and then [store] in a single Async cycle *)
val initialize_and_store
  :  t
  -> Principal.t
  -> Credentials.t list
  -> unit Deferred.Or_error.t

(** check to see if the supplied credentials are already cached. If not, call [store]. All
    this is done in a single Async cycle. *)
val store_if_not_in_cache
  :  t
  -> request:Credentials.t
  -> Credentials.t
  -> unit Deferred.Or_error.t

(** The returned [Credentials.t] are stored in [t].

    [tag_error_with_all_credentials] will decorate errors with a list of all credentials
    in [t]. This might be memory and cpu intensive when there are a lot of credentials in
    [t]. Default: [Config.verbose_errors].

    [ensure_cached_valid_for_at_least] is the amount of time a ticket must be valid for if
    it is taken directly from the cache (i.e. KRB5_GC_CACHED was supplied as a [flag]).
    Default: 10min. *)
val get_credentials
  :  ?tag_error_with_all_credentials:bool
  -> ?ensure_cached_valid_for_at_least:Time_float.Span.t
  -> flags:Krb_flags.Get_credentials.t list
  -> t
  -> request:Credentials.t
  -> Credentials.t Deferred.Or_error.t

val get_cached_tgt
  :  ?ensure_valid_for_at_least:Time_float.Span.t
  -> t
  -> Credentials.t Deferred.Or_error.t


val renew : t -> Credentials.t -> Credentials.t Deferred.Or_error.t

module Expert : sig
  val new_unique : Cache_type.t -> t Deferred.Or_error.t
  val cache_match : Principal.t -> t Deferred.Or_error.t
  val cache_type : t -> Cache_type.t Deferred.t
  val resolve : string -> t Deferred.Or_error.t
  val full_name : t -> string
  val creds : t -> Credentials.t list Deferred.Or_error.t

  (** See docs for [get_credentials]. The difference is that this function can get fresh
      tickets from the KDC where [principal t] is the server principal, rather than the
      client. The client may be any existing principal. *)
  val get_credentials_for_user
    :  ?tag_error_with_all_credentials:bool
    -> ?ensure_cached_valid_for_at_least:Time_float.Span.t
    -> flags:Krb_flags.Get_credentials.t list
    -> t
    -> request:Credentials.t
    -> Credentials.t Deferred.Or_error.t
end

module Raw : sig
  type t
end

val to_raw : t -> Raw.t
