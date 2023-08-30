open! Core
open Async

module type S = sig
  type protocol_backend

  module Connection : T

  module Server : sig
    val serve
      :  authorize:Authorize.t
      -> principal:Principal.Name.t
      -> client_addr:Socket.Address.Inet.t
      -> protocol_backend
      -> Connection.t Protocol_intf.serve_res
  end

  module Client : sig
    val handshake
      :  authorize:Authorize.t
      -> principal:Principal.Name.t
      -> server_addr:Socket.Address.Inet.t
      -> protocol_backend
      -> (Connection.t * unit Or_error.t) Deferred.Or_error.t
  end
end

module type Test_mode_protocol = sig
  module type S = S

  module Make (Backend : Protocol_backend_intf.S) :
    S
      with type protocol_backend = Backend.t
       and type Connection.t = Protocol.Make(Backend).Connection.t
end
