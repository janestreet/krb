open! Core

module Ap_req : sig
  type t =
    | AP_OPTS_USE_SESSION_KEY
    (** Use a tgt's session key (instead of server key) to encrypt the service ticket.
        This is used for user to user mode. *)
    | AP_OPTS_MUTUAL_REQUIRED
    (** Mutual authentication is required. This means that the server must prove its
        identity to the client via an AP_REP message. *)
end

module Auth_context : sig
  type t =
    | KRB5_AUTH_CONTEXT_DO_TIME (** Prevent replays with timestamps and replay cache. *)
    | KRB5_AUTH_CONTEXT_RET_TIME (** Save timestamps for application. *)
    | KRB5_AUTH_CONTEXT_DO_SEQUENCE (** Prevent replays with sequence numbers. *)
    | KRB5_AUTH_CONTEXT_RET_SEQUENCE (** Save sequence numbers for application. *)
end

module Get_credentials : sig
  type t =
    | KRB5_GC_CACHED
    (** Want a cached ticket. If this is specified, getting credentials from a cred cache
        that doesn't have them will fail, instead of reaching out to the KDC to get
        them. *)
    | KRB5_GC_USER_USER (** Want a user-user ticket *)
    | KRB5_GC_NO_STORE (** Do not store in credential cache *)
  [@@deriving equal]
end
