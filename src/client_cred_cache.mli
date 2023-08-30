open! Core
open Async
open Import

(** Most programs look for and store Kerberos tickets in the default cred cache, commonly
    a file on disk. This has the following properties:

    (1) If a process (intentionally or unintentionally) corrupts this file, it has
    far-reaching effects
    (2) Tickets are shared across processes. If one process gets a service ticket, another
    process will subsequently find that ticket in its credential cache.

    In order to mitigate the effects of (1) without compromising the benefits of (2), we
    use a MEMORY cred cache (unless otherwise provided). In order to achieve sharing, we
    make sure to read/write service tickets from/to the default cred cache.

    libkrb5 takes out POSIX locks when messing around with file caches, so it is safe for
    multiple processes to store tickets. See [open_cache_file] and [close_cache_file] in
    src/lib/krb5/ccache/cc_file.c.
*)
type t [@@deriving sexp_of]

val of_cred_cache : Internal.Cred_cache.t -> t Deferred.Or_error.t
val in_memory : unit -> t Deferred.Or_error.t
val cred_cache : t -> Internal.Cred_cache.t

(** If [t] was created using [of_cred_cache], this just calls
    [Internal.Cred_cache.get_credentials].

    If [t] was created using [in_memory], then we try to get a ticket in the following
    order:

    (1) Check for a cached ticket in the memory cache
    (2) Call [Internal.Cred_cache.get_credentials] on the default cache. If this succeeds,
    store the ticket in the memory cache.
    (3) Get a ticket using the memory cache's TGT.

    If cases (1) or (2) succeed, then both the memory cache and the default cache will
    have the ticket.

    In case (3), only the memory cache will have the ticket. *)
val get_credentials
  :  flags:Internal.Krb_flags.Get_credentials.t list
  -> t
  -> request:Internal.Credentials.t
  -> (Internal.Credentials.t
     * [ `Error_getting_creds_from_default_cache of Error.t option ])
     Deferred.Or_error.t

module For_testing : sig
  val create
    :  memory_cache:Internal.Cred_cache.t
    -> default_cache:Internal.Cred_cache.t
    -> t

  val cred_caches : t -> Internal.Cred_cache.t list
end
