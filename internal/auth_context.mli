open! Core
open Async

(** [krb5_auth_context]

    Holds context related to an authenticated connection (e.g. session key) *)
type t

(** See ../src/conn_type.mli for documentation *)
module Safe : sig
  val encode : t -> Bigsubstring.t -> Bigstring.t Deferred.Or_error.t
  val decode : t -> Bigsubstring.t -> Bigstring.t Deferred.Or_error.t
end

module Priv : sig
  val encode : t -> Bigsubstring.t -> Bigstring.t Deferred.Or_error.t
  val decode : t -> Bigsubstring.t -> Bigstring.t Deferred.Or_error.t
end

module Ap_req : sig
  type t = Bigstring.t [@@deriving bin_io]
end

module Ap_rep : sig
  type t [@@deriving bin_io]
end

module Krb_cred : sig
  type t [@@deriving bin_io]
end

type 'a with_inets =
  local_inet:Socket.Address.Inet.t -> remote_inet:Socket.Address.Inet.t -> 'a

module V0 : sig
  module Client : sig
    type 'a with_init_args =
      Cred_cache.t -> Krb_flags.Ap_req.t list -> service:string -> hostname:string -> 'a

    (** Construct a service principal name and obtain credentials using the TGT in the
        supplied cred cache. Then create a KRB_AP_REQ with the obtained credentials. *)
    val init : (t * Ap_req.t) Deferred.Or_error.t with_inets with_init_args

    val init_without_addrs : Ap_req.t Deferred.Or_error.t with_init_args
  end

  module Service : sig
    type 'a with_init_args =
      Principal.t
      -> [ `Keytab of Keytab.t | `User_to_user of Keyblock.t ]
      -> ap_req:Ap_req.t
      -> 'a

    (** Read the KRB_AP_REQ. To decrypt, either look for a key in the supplied keytab, or
        use the supplied keyblock. Return the client's principal. *)
    val init : (t * Principal.t) Deferred.Or_error.t with_inets with_init_args
  end
end

module V1 : sig
  module Client : sig
    type 'a with_init_args = Krb_flags.Ap_req.t list -> Credentials.t -> 'a

    (** Use the supplied credentials to create a KRB_AP_REQ message *)
    val init : (t * Ap_req.t) Deferred.Or_error.t with_inets with_init_args
  end

  module Service : sig
    type 'a with_init_args = 'a V0.Service.with_init_args

    (** See [V0.Service.init] *)
    val init : (t * Principal.t) Deferred.Or_error.t with_inets with_init_args
  end
end

module Client : sig
  type 'a with_init_args = 'a V1.Client.with_init_args

  (** See [V1.Client.init] *)
  val init : (t * Ap_req.t) Deferred.Or_error.t with_inets with_init_args

  (** Without setting addrs on the auth context, you can't encode/decode messages. Thus,
      you don't get back a [t]. However, you can still use the [ap_req] as a way for the
      client to claim its identity. *)
  val init_without_addrs : Ap_req.t Deferred.Or_error.t with_init_args

  (** Read an AP_REP message from the server.  This authenticates the server to the
      client *)
  val read_and_verify_ap_rep : t -> ap_rep:Ap_rep.t -> unit Deferred.Or_error.t

  (** Create a KRB-CRED message. This will be sent by the client to forward its
      credentials (really just TGT) to the server. *)
  val make_krb_cred
    :  t
    -> forwardable:bool
    -> client:Principal.t
    -> Cred_cache.t
    -> Krb_cred.t Deferred.Or_error.t
end

module Service : sig
  type 'a with_init_args = 'a V0.Service.with_init_args

  (** See [V0.Service.init] *)
  val init : (t * Principal.t) Deferred.Or_error.t with_inets with_init_args

  (** See [Client.init_without_addrs] *)
  val init_without_addrs : Principal.t Deferred.Or_error.t with_init_args

  (** Create an AP_REP message. This will be sent by the server to authenticate itself to
      the client. *)
  val make_ap_rep : t -> Ap_rep.t Deferred.Or_error.t

  (** read a KRB-CRED message and store the contained credentials into a credential
      cache *)
  val read_krb_cred_into_cred_cache
    :  t
    -> Krb_cred.t
    -> Cred_cache.t
    -> unit Deferred.Or_error.t
end
