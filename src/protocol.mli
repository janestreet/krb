open! Core
open Async
open Import

module type S = Protocol_intf.S

val supported_versions : int list

module Make (Backend : Protocol_backend_intf.S) :
  S with type protocol_backend := Backend.t

module Connection : sig
  include Protocol_intf.Connection with type t = Make(Protocol_backend_async).Connection.t

  val create_for_test_mode
    :  reader:Reader.t
    -> writer:Writer.t
    -> conn_type:Conn_type.t
    -> my_principal:Principal.Name.t
    -> peer_principal:Principal.Name.t
    -> t

  val reader : t -> Reader.t
  val writer : t -> Writer.t

  val make_krb_cred
    :  t
    -> forwardable:bool
    -> Internal.Auth_context.Krb_cred.t Deferred.Or_error.t

  val read_krb_cred
    :  t
    -> Internal.Auth_context.Krb_cred.t
    -> Internal.Cred_cache.t Deferred.Or_error.t
end

module Server : sig
  val serve
    : (Reader.t -> Writer.t -> Connection.t Protocol_intf.serve_res)
        Protocol_intf.with_serve_krb_args
end

module Client : sig
  val connect
    : (?override_supported_versions:int list
       -> ?on_connection:
         (Socket.Address.Inet.t -> Server_principal.t -> [ `Accept | `Reject ])
       -> client_cred_cache:Client_cred_cache.t
       -> accepted_conn_types:Conn_type_preference.t
       -> Socket.Address.Inet.t Tcp.Where_to_connect.t
       -> Connection.t Deferred.Or_error.t)
        Tcp.with_connect_options
end

module For_test : sig
  module Client : sig
    module V4_header : sig
      type t [@@deriving bin_io, sexp]

      val ap_request : t -> Bigstring.Stable.V1.t
    end
  end

  module Server : sig
    module V4_header : sig
      type t [@@deriving bin_io, sexp]

      val principal : t -> Principal.Name.t
    end
  end
end
