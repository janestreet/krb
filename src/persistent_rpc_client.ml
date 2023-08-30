open Core
open Async

module Create_helper (T : sig
  include Persistent_connection.S

  val conn_of_rpc_connection
    :  Kerberized_rpc.Connection.t Deferred.Or_error.t
    -> conn Deferred.Or_error.t
end) =
struct
  include T

  let create'
    ~server_name
    ?log
    ?on_event
    ?retry_delay
    ?max_message_size
    ?handshake_timeout
    ?heartbeat_config
    ?krb_mode
    ?bind_to_address
    ?implementations
    ?description
    ?cred_cache
    ~authorize
    get_addr
    =
    T.create
      ~server_name
      ?log
      ?on_event
      ?retry_delay
      ~connect:(fun host_and_port ->
        let host, port = Host_and_port.tuple host_and_port in
        Kerberized_rpc.Connection.client
          ?max_message_size
          ?handshake_timeout
          ?heartbeat_config
          ?implementations
          ?description
          ?cred_cache
          ?krb_mode
          ~authorize
          (Tcp.Where_to_connect.of_host_and_port ?bind_to_address { host; port })
        |> T.conn_of_rpc_connection)
      ~address:(module Host_and_port)
      get_addr
  ;;
end

module Rpc = Create_helper (struct
  include Persistent_connection.Rpc

  let conn_of_rpc_connection = Fn.id
end)

module Versioned_rpc = Create_helper (struct
  include Persistent_connection.Versioned_rpc

  let conn_of_rpc_connection =
    Deferred.Or_error.bind ~f:Versioned_rpc.Connection_with_menu.create
  ;;
end)
