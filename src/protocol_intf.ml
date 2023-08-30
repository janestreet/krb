open! Core
open Async
open Import

module type Connection = sig
  type protocol_backend
  type t

  val create_for_test_mode
    :  backend:protocol_backend
    -> conn_type:Conn_type.t
    -> my_principal:Cross_realm_principal_name.t
    -> peer_principal:Cross_realm_principal_name.t
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

  module Cross_realm : sig
    val my_principal : t -> Cross_realm_principal_name.t
    val peer_principal : t -> Cross_realm_principal_name.t
  end
end

type 'a with_serve_krb_args =
  ?override_supported_versions:int list
  -> ?additional_magic_numbers:int list
  -> authorize:Authorize.t
  -> conn_type_preference:Conn_type_preference.t
  -> principal:Principal.t
  -> peer:Socket.Address.Inet.t
  -> [ `Service of Keytab.t | `User_to_user_via_tgt of Internal.Credentials.t ]
  -> 'a

type 'conn serve_res =
  ( 'conn
  , [ `Krb_error of Error.t | `Handshake_error of Handshake_error.t | `Rejected_client ]
  )
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
      -> authorize:Authorize.t
      -> client_cred_cache:Client_cred_cache.t
      -> conn_type_preference:Conn_type_preference.t
      -> peer:Socket.Address.Inet.t
      -> protocol_backend
      -> Connection.t Deferred.Or_error.t
  end
end

module type Server_header = sig
  type t [@@deriving bin_io]
end

module type Client_header = sig
  type t [@@deriving bin_io]
end

module type Stable_protocol = sig
  module Mode : sig
    type t [@@deriving bin_io]
  end

  module Server_header : Server_header
  module Client_header : Client_header
end

module type Protocol = sig
  module type Connection = Connection
  module type S = S
  module type Stable_protocol = Stable_protocol

  val supported_versions : int list

  module Make (Backend : Protocol_backend_intf.S) :
    S with type protocol_backend = Backend.t

  module Stable : sig
    module V1 : Stable_protocol
    module V2 : Stable_protocol
    module V3 : Stable_protocol

    module V4 : sig
      include Stable_protocol

      module Server_header : sig
        type t [@@deriving sexp]

        val principal : t -> Principal.Name.t
        val accepted_conn_types : t -> Conn_type_preference.t

        include Server_header with type t := t
      end

      module Client_header : sig
        type t [@@deriving sexp]

        val ap_request : t -> Bigstring.Stable.V1.t
        val accepted_conn_types : t -> Conn_type_preference.t

        include Client_header with type t := t
      end
    end

    module V5 : Stable_protocol
  end
end
