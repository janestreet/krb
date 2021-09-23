open! Core
open! Async
open Import

(** A credentials cache holds Kerberos credentials (aka tickets) for a particular
    principal. At a high level, they prevent users from having to constantly talk to the
    KDC to get tickets (until the existing ones expire).

    There are many different types of credential caches. The common ones are:

    FILE   : Credentials are stored for a single principal in a file
    DIR    : Credentials are stored for multiple principals in a directory
    MEMORY : Credentials are stored for a single principal in memory
*)

type t = Internal.Cred_cache.t

(** [default] returns Kerberos's notion of a "default" credential cache. This is
    determined by the following steps, in descending order:
    - KRB5CCNAME environment variable
    - default_ccache_name variable in [libdefaults] in /etc/krb5.conf
    - DEFCCNAME build parameter (usually FILE:/tmp/krb5cc_%{uid}) *)
val default : unit -> t Deferred.Or_error.t

(** The principal associated with [default] *)
val default_principal : unit -> Principal.Name.t Deferred.Or_error.t

(** The principal associated with the credential cache supplied *)
val principal : t -> Principal.Name.t Deferred.Or_error.t

(** A shared MEMORY [t] for [principal]. If a previous call succeeded for the same
    [principal], the same [t] is returned. The returned [t] is never freed, so this
    function should not be called with an unbounded number of unique [principal]s. *)
val in_memory_for_principal : Principal.Name.t -> t Deferred.Or_error.t

(** Initialize [t] with the given principal and credentials. This function updates [t]
    atomically for FILE cred caches. *)
val initialize_with_creds
  :  t
  -> Principal.t
  -> Internal.Credentials.t list
  -> unit Deferred.Or_error.t

(** Initializes the shared MEMORY cache associated with the principal of [t]
    (see [in_memory_for_principal]) with the credentials from [t]. *)
val initialize_in_memory_with_creds_from : t -> t Deferred.Or_error.t

module Cross_realm : sig
  val principal : t -> Cross_realm_principal_name.t Deferred.Or_error.t
  val in_memory_for_principal : Cross_realm_principal_name.t -> t Deferred.Or_error.t
end

module Expert : sig
  (** This function uses the S4U2Self Kerberos extension to get a ticket from the
      passed-in principal to the owner of [server_cred_cache] (or the default cred cache,
      if that is [None]).

      This is quite different from a normal ticket - the user you currently have
      credentials for is the server, not the client, in the resulting ticket. This means
      that you are impersonating the client - but only to other apps running as the same
      principal as you! This can be useful for keeping internal communication within an
      app Kerberized, even if it is on behalf of other users, without having to have a
      more explicit trust relationship and tag RPCs with the "acting" user.

      This is also different from a normal cred-cache, as it will never contain a TGT! The
      cache itself is tagged with this fact, so functions like
      [Tgt.keep_valid_indefinitely] will fail if they see a cache like this, and others
      like [Cred_cache.keep_valid] will behave differently (in that case, by renewing the
      expected non-TGT).

      NOTE: If the principal you are requesting is also the server's principal, this
      function will return an error. *)
  val in_memory_for_principal_with_s4u2self_cred
    :  ?server_cred_cache:t
    -> Principal.Name.t
    -> t Deferred.Or_error.t

  (** Looks for a ticket in [t] where the server is the named principal. If there is one,
      ensure it is valid for at least [valid_for_at_least], renewing if it isn't.

      If this is a TGT-holding cache (that is, if [t] didn't originate from
      [in_memory_for_prinicpal_with_s4u2self_cred]), this will fail. *)
  val ensure_s4u2self_valid
    :  ?valid_for_at_least:Time.Span.t (** default: 10m *)
    -> ?server_cred_cache:t
    -> t
    -> Principal.Name.t
    -> unit Deferred.Or_error.t
end
