open! Core
open Async

module type S = Test_mode_protocol_intf.S

module Make (Backend : Protocol_backend_intf.S) :
  S
  with type protocol_backend := Backend.t
   and type Connection.t = Protocol.Make(Backend).Connection.t

module Client : sig
  val connect
    : (?on_connection:
        (Socket.Address.Inet.t -> Server_principal.t -> [ `Accept | `Reject ])
       -> principal:Principal.Name.t
       -> Socket.Address.Inet.t Tcp.Where_to_connect.t
       -> Protocol.Connection.t Deferred.Or_error.t)
        Tcp.with_connect_options
end

module Server : sig
  val serve
    :  ?on_connection:
      (Socket.Address.Inet.t -> Client_principal.t -> [ `Accept | `Reject ])
    -> principal:Principal.Name.t
    -> client_addr:Socket.Address.Inet.t
    -> Reader.t
    -> Writer.t
    -> Protocol.Connection.t Protocol_intf.serve_res
end
