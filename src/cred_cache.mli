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
