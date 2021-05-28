open! Core
open! Async
open! Import

module Tcp : sig
  type on_error :=
    [ `Call of Socket.Address.Inet.t -> exn -> unit
    | `Ignore
    | `Raise
    ]

  (** refer to [Kerberized_tcp] and [Kerberized_rpc] for details on these arguments. *)
  val serve
    :  ?max_message_size:int
    -> (?on_kerberos_error:on_error
        -> ?on_handshake_error:on_error
        -> ?on_handler_error:on_error
        -> ?on_done_with_internal_buffer:[ `Do_nothing | `Zero ]
        -> authorize:Authorize.t
        -> where_to_listen:Tcp.Where_to_listen.inet
        -> krb_mode:Mode.Server.t
        -> (Socket.Address.Inet.t
            -> Rpc.Transport.t
            -> Async_protocol.Connection.t
            -> unit Deferred.t)
        -> (Socket.Address.Inet.t, int) Tcp.Server.t Deferred.Or_error.t)
         Kerberized_tcp.async_tcp_server_args

  (** refer to [Kerberized_tcp] and [Kerberized_rpc] for details on these arguments. *)
  val serve_with_anon
    :  ?max_message_size:int
    -> (?on_kerberos_error:on_error
        -> ?on_handshake_error:on_error
        -> ?on_handler_error:on_error
        -> ?on_done_with_internal_buffer:[ `Do_nothing | `Zero ]
        -> authorize:Authorize.Anon.t
        -> where_to_listen:Tcp.Where_to_listen.inet
        -> krb_mode:Mode.Server.t
        -> (Socket.Address.Inet.t
            -> Rpc.Transport.t
            -> Async_protocol.Connection.t option
            -> unit Deferred.t)
        -> (Socket.Address.Inet.t, int) Tcp.Server.t Deferred.Or_error.t)
         Kerberized_tcp.async_tcp_server_args

  (** refer to [Kerberized_tcp] and [Kerberized_rpc] for details on these arguments. *)
  val create_handler
    :  ?max_message_size:int
    -> ?on_kerberos_error:on_error
    -> ?on_handshake_error:on_error
    -> ?on_handler_error:on_error
    -> ?on_done_with_internal_buffer:[ `Do_nothing | `Zero ]
    -> authorize:Authorize.t
    -> krb_mode:Mode.Server.t
    -> (Socket.Address.Inet.t
        -> Rpc.Transport.t
        -> Async_protocol.Connection.t
        -> unit Deferred.t)
    -> (Socket.Address.Inet.t -> Reader.t -> Writer.t -> unit Deferred.t)
         Deferred.Or_error.t

  (** refer to [Kerberized_tcp] and [Kerberized_rpc] for details on these arguments. *)
  val client
    :  ?max_message_size:int
    -> ?timeout:Time_ns.Span.t
    -> ?cred_cache:Cred_cache.t
    -> ?buffer_age_limit:Writer.buffer_age_limit
    -> ?on_done_with_internal_buffer:[ `Do_nothing | `Zero ]
    -> ?krb_mode:Mode.Client.t
    -> authorize:Authorize.t
    -> Tcp.Where_to_connect.inet
    -> (Rpc.Transport.t * Async_protocol.Connection.t) Deferred.Or_error.t
end

module Internal : sig
  module Tcp : sig
    val client
      :  ?override_supported_versions:int list
      -> ?max_message_size:int
      -> ?timeout:Time_ns.Span.t
      -> ?cred_cache:Cred_cache.t
      -> ?buffer_age_limit:Writer.buffer_age_limit
      -> ?on_done_with_internal_buffer:[ `Do_nothing | `Zero ]
      -> ?krb_mode:Mode.Client.t
      -> authorize:Authorize.t
      -> Async.Tcp.Where_to_connect.inet
      -> (Rpc.Transport.t * Async_protocol.Connection.t) Deferred.Or_error.t
  end
end
