open Core
open Async
include Persistent_connection.Rpc

type 'a persistent_connection_args =
  server_name:string
  -> ?log:Log.t
  -> ?on_event:(Event.t -> unit Deferred.t)
  -> ?retry_delay:(unit -> Time.Span.t)
  -> 'a

(* shadow included [create'] *)
let create'
      ~server_name
      ?log
      ?on_event
      ?retry_delay
      ?max_message_size
      ?handshake_timeout
      ?heartbeat_config
      ~krb_mode
      ?bind_to_address
      ?implementations
      ?description
      ?cred_cache
      ?on_connection
      get_addr
  =
  create
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
        ?on_connection
        ~krb_mode
        (Tcp.Where_to_connect.of_host_and_port ?bind_to_address { host; port }))
    get_addr
;;
