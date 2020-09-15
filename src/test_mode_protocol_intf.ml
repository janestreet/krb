open! Core
open Async

module type S = sig
  type protocol_backend

  module Connection : Protocol_intf.Connection

  module Server : sig
    val serve
      :  ?on_connection:
        (Socket.Address.Inet.t -> Client_principal.t -> [ `Accept | `Reject ])
      -> principal:Principal.Name.t
      -> client_addr:Socket.Address.Inet.t
      -> protocol_backend
      -> Connection.t Protocol_intf.serve_res
  end

  module Client : sig
    val handshake
      :  ?on_connection:
        (Socket.Address.Inet.t -> Server_principal.t -> [ `Accept | `Reject ])
      -> principal:Principal.Name.t
      -> server_addr:Socket.Address.Inet.t
      -> protocol_backend
      -> (Connection.t * unit Or_error.t) Deferred.Or_error.t
  end
end
