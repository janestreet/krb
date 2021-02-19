open! Core
open Async

type protocol_backend = Protocol_backend_async.t

module Connection : sig
  include Protocol.Connection with type protocol_backend = protocol_backend

  val reader : t -> Reader.t
  val writer : t -> Writer.t
end

include
  Protocol_with_test_mode_intf.S
  with type protocol_backend := Protocol_backend_async.t
   and module Connection := Connection
