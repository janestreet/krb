open! Core
open! Async

(** Kerberos clients send encrypted tickets for servers. One of the central underpinning
    of Kerberos is that only the KDC and the target server know this secret encryption
    key.

    A [Server_key_source.t] represents which key is used to encrypt service tickets. The
    [Keytab] variant should be used for as-users. The [Tgt] variant should be used for
    human users. [default ()] will make this choice for you based on the currently running
    user.

    See [../doc/index.mkd] for more information on how Kerberos works.
*)

type t =
  | Tgt
  (** Use the session key associated with the server's ticket granting ticket (TGT). The
      user must have a valid TGT in its cred cache. This is the recommended setup for
      human users that don't have keytabs. *)
  | Keytab of Principal.Name.t * Keytab.Path.t
  (** Use the password-derived key for the specified principal that is stored in the
      specified keytab. *)
[@@deriving compare, hash, sexp_of]


(** Make a best effort attempt to validate [t]. This can be used as a way to fail early
    after getting a [t] from the command line. It is automatically called with
    [~refresh_tgt:()] before all Tcp and Rpc client connections.

    [refresh_tgt] will start a background job to refresh credentials in the [Keytab] case.

    Note: it is still possible for this function to return a success but a later call
    that uses [t] to fail. This might be because a ticket has expired or because some
    other process has been mucking around with the credential cache. *)
val best_effort_validate
  :  ?refresh_tgt:unit
  -> cred_cache:Cred_cache.t
  -> t
  -> unit Deferred.Or_error.t

(** [principal t] returns the [Principal.t] that will be used
    to start kerberized services  *)
val principal : t -> Principal.t Deferred.Or_error.t

module Stable : sig
  module V2 : Stable_without_comparator with type t = t
end
