open! Core
open Async
open Import

module type Connection = sig
  type protocol_backend
  type t

  val create_for_test_mode
    :  backend:protocol_backend
    -> conn_type:Conn_type.t
    -> my_principal:Principal.Name.t
    -> peer_principal:Principal.Name.t
    -> t

  val backend : t -> protocol_backend
  val auth_context : t -> [ `Test_mode | `Prod of Internal.Auth_context.t ]
  val conn_type : t -> Conn_type.t
  val my_principal : t -> Principal.Name.t
  val peer_principal : t -> Principal.Name.t
  val protocol_version : t -> [ `Test_mode | `Versioned of int ]
  val can_forward_creds : t -> bool

  val make_krb_cred
    :  t
    -> forwardable:bool
    -> Internal.Auth_context.Krb_cred.t Deferred.Or_error.t

  val read_krb_cred
    :  t
    -> Internal.Auth_context.Krb_cred.t
    -> Internal.Cred_cache.t Deferred.Or_error.t
end

type 'a with_serve_krb_args =
  ?on_connection:(Socket.Address.Inet.t -> Client_principal.t -> [ `Accept | `Reject ])
  -> accepted_conn_types:Conn_type_preference.t
  -> principal:Principal.t
  -> peer:Socket.Address.Inet.t
  -> [ `Service of Keytab.t | `User_to_user_via_tgt of Internal.Credentials.t ]
  -> 'a

type 'conn serve_res =
  ( 'conn
  , [ `Krb_error of Error.t | `Handshake_error of Error.t | `Rejected_client ] )
    Deferred.Result.t

module type S = sig
  type protocol_backend

  module Connection : Connection with type protocol_backend = protocol_backend

  module Server : sig
    (** Perform handshake as a server. Becomes determined when done, and ready for
        sending/receiving user data. *)
    val handshake : (protocol_backend -> Connection.t serve_res) with_serve_krb_args
  end

  module Client : sig
    (** Perform handshake as a client. Becomes determined when done, and ready for
        sending/receiving user data. *)
    val handshake
      :  ?override_supported_versions:int list
      -> on_connection:
           (Socket.Address.Inet.t -> Server_principal.t -> [ `Accept | `Reject ])
      -> client_cred_cache:Client_cred_cache.t
      -> accepted_conn_types:Conn_type_preference.t
      -> peer:Socket.Address.Inet.t
      -> protocol_backend
      -> Connection.t Deferred.Or_error.t
  end
end

module type Protocol = sig
  module type Connection = Connection
  module type S = S

  val supported_versions : int list

  module Make (Backend : Protocol_backend_intf.S) :
    S with type protocol_backend = Backend.t

  module For_test : sig
    module Client : sig
      module V4_header : sig
        type t [@@deriving bin_io, sexp]

        val ap_request : t -> Bigstring.Stable.V1.t
        val accepted_conn_types : t -> Conn_type_preference.t
      end
    end

    module Server : sig
      module V4_header : sig
        type t [@@deriving bin_io, sexp]

        val principal : t -> Principal.Name.t
        val accepted_conn_types : t -> Conn_type_preference.t
      end
    end
  end
end
