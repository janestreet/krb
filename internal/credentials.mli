open! Core
open Async

(** [krb5_creds]

    A ticket that allows one to connect as a particular client principal to a particular
    server principal for a given time using a particular session key whenever encryption
    is needed for client/server communication. *)
type t [@@deriving sexp_of]


(** From RFC 4120, a [ticket] is:

    "A record that helps a client authenticate itself to a server; it contains the client's
    identity, a session key, a timestamp, and other information, all sealed using the
    server's secret key.  It only serves to authenticate a client when presented along
    with a fresh Authenticator."

    Ultimately, it's some bytes that are used in authentication and come from a ticket
    request to the KDC.

    The odd thing regarding this type is that it is both used to represent a request for
    credentials (no tickets specified) and as the retrieved credentials (contains a
    ticket).

    As for [second_ticket], it's a special ticket that is used in user-to-user
    authentication. It is set to the TGT of the server when requesting credentials from
    the KDC.

    You should only need to use this function if you're doing something low-level
    manually. *)
val create
  :  ?ticket:string
  -> ?second_ticket:string
  -> client:Principal.t
  -> server:Principal.t
  -> unit
  -> t Deferred.Or_error.t


(** [of_password] and [of_keytab] request tickets from the KDC.

    [options] is used to override default lifetimes and flags for the returned ticket.

    [tkt_service] specifies what ticket to acquire. If not specified, it defaults to the
    KDC's ticket granting service (i.e. the returned ticket is a TGT).

    [principal] is the requesting principal. *)
val of_password
  :  ?options:Get_init_creds_opts.t
  -> ?tkt_service:string
  -> Principal.t
  -> string
  -> t Deferred.Or_error.t

val of_keytab
  :  ?options:Get_init_creds_opts.t
  -> ?tkt_service:string
  -> Principal.t
  -> Keytab.t
  -> t Deferred.Or_error.t


(** [check_password principal ~password] checks with the KDC that [principal]'s password
    is [password] *)
val check_password : Principal.t -> password:string -> unit Deferred.Or_error.t

val client : t -> Principal.t
val server : t -> Principal.t

(** [is_skey t] iff the server should decrypt the ticket with the session key of its tgt
    (user-to-user) *)
val is_skey : t -> bool

val ticket : t -> Ticket.t Deferred.Or_error.t
val ticket_string : t -> string


val second_ticket : t -> string
val starttime : t -> Time.t

(** valid until this time *)
val endtime : t -> Time.t

val renew_until : t -> Time.t

(** the session key *)
val keyblock : t -> Keyblock.t Deferred.Or_error.t

module Flags : sig
  type t =
    { forwardable : bool
    ; proxiable : bool
    }
  [@@deriving sexp_of]
end

val flags : t -> Flags.t

module Raw : sig
  type t

  val free : Context.t -> t -> unit
end

val to_raw : t -> Raw.t
val of_raw : Raw.t -> t Deferred.Or_error.t

module Expert : sig
  val of_keytab
    :  ?options:Get_init_creds_opts.t
    -> ?tkt_service:string
    -> Principal.t
    -> Keytab.t
    -> (t, [ `Auth_failure of Error.t | `Non_auth_failure of Error.t ]) Deferred.Result.t
end
