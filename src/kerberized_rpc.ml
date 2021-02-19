open Core
open Async
open Import
module Auth_context = Internal.Auth_context
module Transport = Kerberized_rpc_transport

type 'a async_rpc_args =
  ?max_message_size:int
  -> ?handshake_timeout:Time.Span.t
  -> ?heartbeat_config:Rpc.Connection.Heartbeat_config.t
  -> 'a

module Connection = struct
  type t = Rpc.Connection.t

  let handle_client
        ?heartbeat_config
        ?handshake_timeout
        initial_connection_state
        implementations
    =
    Kerberized_rpc_over_protocol.handle_client
      (module Async_protocol.Connection)
      ?heartbeat_config
      ?handshake_timeout
      initial_connection_state
      implementations
  ;;

  let serve
        ?max_message_size
        ?handshake_timeout
        ?heartbeat_config
        ?max_connections
        ?backlog
        ?drop_incoming_connections
        ?buffer_age_limit
        ?on_kerberos_error
        ?(on_handshake_error = `Ignore)
        ?on_connection
        ?on_done_with_internal_buffer
        ~implementations
        ~initial_connection_state
        ~where_to_listen
        ~krb_mode
        ()
    =
    Kerberized_rpc_transport.Tcp.serve
      ?max_message_size
      ?max_connections
      ?backlog
      ?drop_incoming_connections
      ?buffer_age_limit
      ?on_kerberos_error
      ~on_handshake_error
      (* A TCP handler error is an RPC handshake error, since the handler just does
         a handshake. *)
      ~on_handler_error:on_handshake_error
      ?on_connection
      ?on_done_with_internal_buffer
      ~krb_mode
      ~where_to_listen
      (handle_client
         ?heartbeat_config
         ?handshake_timeout
         initial_connection_state
         implementations
       |> Staged.unstage)
  ;;

  let handle_client_with_anon
        ?heartbeat_config
        ?handshake_timeout
        initial_connection_state
        implementations
    =
    Kerberized_rpc_over_protocol.handle_client_with_anon
      (module Async_protocol.Connection)
      ?heartbeat_config
      ?handshake_timeout
      initial_connection_state
      implementations
  ;;

  let create_handler
        ?max_message_size
        ?handshake_timeout
        ?heartbeat_config
        ?on_kerberos_error
        ?(on_handshake_error = `Ignore)
        ?on_connection
        ?on_done_with_internal_buffer
        ~implementations
        ~initial_connection_state
        krb_mode
    =
    Kerberized_rpc_transport.Tcp.create_handler
      ?max_message_size
      ?on_kerberos_error
      ~on_handshake_error
      ~on_handler_error:on_handshake_error
      ?on_connection
      ?on_done_with_internal_buffer
      ~krb_mode
      (handle_client
         ?heartbeat_config
         ?handshake_timeout
         initial_connection_state
         implementations
       |> Staged.unstage)
  ;;

  let serve_with_anon
        ?max_message_size
        ?handshake_timeout
        ?heartbeat_config
        ?max_connections
        ?backlog
        ?drop_incoming_connections
        ?buffer_age_limit
        ?on_kerberos_error
        ?(on_handshake_error = `Ignore)
        ?on_connection
        ?on_done_with_internal_buffer
        ~implementations
        ~initial_connection_state
        ~where_to_listen
        ~krb_mode
        ()
    =
    Kerberized_rpc_transport.Tcp.serve_with_anon
      ?max_message_size
      ?max_connections
      ?backlog
      ?drop_incoming_connections
      ?buffer_age_limit
      ?on_kerberos_error
      ~on_handshake_error
      ~on_handler_error:on_handshake_error
      ?on_connection
      ?on_done_with_internal_buffer
      ~krb_mode
      ~where_to_listen
      (handle_client_with_anon
         ?heartbeat_config
         ?handshake_timeout
         initial_connection_state
         implementations
       |> Staged.unstage)
  ;;

  module Internal = struct
    let client
          ?override_supported_versions
          ?max_message_size
          ?(handshake_timeout =
            Time_ns.Span.to_span_float_round_nearest
              Async_rpc_kernel.Async_rpc_kernel_private.default_handshake_timeout)
          ?heartbeat_config
          ?implementations
          ?description
          ?cred_cache
          ?buffer_age_limit
          ?on_connection
          ?on_credential_forwarding_request
          ?on_done_with_internal_buffer
          ?krb_mode
          where_to_connect
      =
      let finish_handshake_by = Time.add (Time.now ()) handshake_timeout in
      Kerberized_rpc_transport.Internal.Tcp.client
        ?max_message_size
        ~timeout:(Time_ns.Span.of_span_float_round_nearest handshake_timeout)
        ?cred_cache
        ?override_supported_versions
        ?on_connection
        ?buffer_age_limit
        ?on_done_with_internal_buffer
        ?krb_mode
        where_to_connect
      >>=? fun (transport, conn) ->
      Kerberized_rpc_over_protocol.client
        (module Async_protocol.Connection)
        ?heartbeat_config
        ?implementations
        ?description
        ?on_credential_forwarding_request
        ~finish_handshake_by
        where_to_connect
        transport
        conn
    ;;
  end

  let client ?max_message_size =
    Internal.client ?override_supported_versions:None ?max_message_size
  ;;

  let with_client
        ?max_message_size
        ?handshake_timeout
        ?heartbeat_config
        ?implementations
        ?description
        ?cred_cache
        ?buffer_age_limit
        ?on_connection
        ?on_credential_forwarding_request
        ?on_done_with_internal_buffer
        ?krb_mode
        where_to_connect
        f
    =
    client
      ?max_message_size
      ?handshake_timeout
      ?heartbeat_config
      ?implementations
      ?description
      ?cred_cache
      ?buffer_age_limit
      ?on_connection
      ?on_credential_forwarding_request
      ?on_done_with_internal_buffer
      ?krb_mode
      where_to_connect
    >>=? fun t ->
    Deferred.Or_error.try_with
      ~run:
        `Schedule
      ~rest:`Log
      (fun () -> f t)
    >>= fun result -> Rpc.Connection.close t >>| fun () -> result
  ;;
end

let%test_module "Ensure test mode works" =
  (module struct
    let serve ~implementations ~initial_connection_state ~where_to_listen ~krb_mode =
      Connection.serve
        ~implementations
        ~initial_connection_state
        ~where_to_listen
        ~krb_mode
        ()
    ;;

    let with_client ~on_connection ~krb_mode where_to_connect f =
      Connection.with_client ~on_connection ~krb_mode where_to_connect f
    ;;

    let%test_unit "Test mode works" =
      Kerberized_rpc_over_protocol.For_testing.ensure_test_mode_works ~serve ~with_client
    ;;
  end)
;;
