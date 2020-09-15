open! Core
open Async
open Import

module type Connection = sig
  type t

  val auth_context : t -> [ `Test_mode | `Prod of Internal.Auth_context.t ]
  val conn_type : t -> Conn_type.t
  val my_principal : t -> Principal.Name.t
  val peer_principal : t -> Principal.Name.t
  val protocol_version : t -> [ `Test_mode | `Versioned of int ]
  val can_forward_creds : t -> bool
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

  module Connection : sig
    include Connection

    val create_for_test_mode
      :  backend:protocol_backend
      -> conn_type:Conn_type.t
      -> my_principal:Principal.Name.t
      -> peer_principal:Principal.Name.t
      -> t
  end

  module Server : sig
    val serve : (protocol_backend -> Connection.t serve_res) with_serve_krb_args
  end

  module Client : sig
    val negotiate_and_setup
      :  ?override_supported_versions:int list
      -> on_connection:
           (Socket.Address.Inet.t -> Server_principal.t -> [ `Accept | `Reject ])
      -> client_cred_cache:Client_cred_cache.t
      -> accepted_conn_types:Conn_type_preference.t
      -> peer:Socket.Address.Inet.t
      -> protocol_backend
      -> [ `Ok of Connection.t ] Deferred.Or_error.t
  end
end
