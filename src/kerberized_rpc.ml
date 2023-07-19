open Core
open Async
open Import
module Transport = Kerberized_rpc_transport

type 'a async_rpc_args =
  ?max_message_size:int
  -> ?handshake_timeout:Time.Span.t
  -> ?heartbeat_config:Rpc.Connection.Heartbeat_config.t
  -> 'a

module Connection = struct
  type t = Rpc.Connection.t

  let handshake_handler_for_rpc = function
    | `Ignore -> `Ignore
    | `Raise -> `Raise
    | `Call f ->
      `Call
        (fun addr exn -> f Handshake_error.Kind.Unexpected_or_no_client_bytes addr exn)
  ;;

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

  module Internal = struct
    let serve
          ?override_supported_versions
          ?additional_magic_numbers
          ?max_message_size
          ?handshake_timeout
          ?heartbeat_config
          ?max_connections
          ?backlog
          ?drop_incoming_connections
          ?buffer_age_limit
          ?on_kerberos_error
          ?(on_handshake_error = `Ignore)
          ?on_done_with_internal_buffer
          ~authorize
          ~implementations
          ~initial_connection_state
          ~where_to_listen
          ~krb_mode
          ()
      =
      Kerberized_rpc_transport.Internal.Tcp.serve
        ?override_supported_versions
        ?additional_magic_numbers
        ?max_message_size
        ?max_connections
        ?backlog
        ?drop_incoming_connections
        ?buffer_age_limit
        ?on_kerberos_error
        ~on_handshake_error
        (* A TCP handler error is an RPC handshake error, since the handler just does
           a handshake. *)
        ~on_handler_error:(handshake_handler_for_rpc on_handshake_error)
        ?on_done_with_internal_buffer
        ~authorize
        ~krb_mode
        ~where_to_listen
        (handle_client
           ?heartbeat_config
           ?handshake_timeout
           initial_connection_state
           implementations
         |> Staged.unstage)
    ;;

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
          ?on_credential_forwarding_request
          ?on_done_with_internal_buffer
          ?krb_mode
          ~authorize
          where_to_connect
      =
      let finish_handshake_by = Time.add (Time.now ()) handshake_timeout in
      Kerberized_rpc_transport.Internal.Tcp.client
        ?max_message_size
        ~timeout:(Time_ns.Span.of_span_float_round_nearest handshake_timeout)
        ?cred_cache
        ?override_supported_versions
        ?buffer_age_limit
        ?on_done_with_internal_buffer
        ?krb_mode
        ~authorize
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

  let serve ?additional_magic_numbers ?max_message_size =
    Internal.serve
      ?additional_magic_numbers
      ?override_supported_versions:None
      ?max_message_size
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
        ?on_done_with_internal_buffer
        ~authorize
        ~implementations
        ~initial_connection_state
        ~krb_mode
        ()
    =
    Kerberized_rpc_transport.Tcp.create_handler
      ?max_message_size
      ?on_kerberos_error
      ~on_handshake_error
      ~on_handler_error:(handshake_handler_for_rpc on_handshake_error)
      ?on_done_with_internal_buffer
      ~authorize
      ~krb_mode
      (handle_client
         ?heartbeat_config
         ?handshake_timeout
         initial_connection_state
         implementations
       |> Staged.unstage)
  ;;

  let create_handler_with_anon
        ?max_message_size
        ?handshake_timeout
        ?heartbeat_config
        ?on_kerberos_error
        ?(on_handshake_error = `Ignore)
        ?on_done_with_internal_buffer
        ~authorize
        ~implementations
        ~initial_connection_state
        ~krb_mode
        ()
    =
    Kerberized_rpc_transport.Tcp.create_handler_with_anon
      ?max_message_size
      ?on_kerberos_error
      ~on_handshake_error
      ~on_handler_error:(handshake_handler_for_rpc on_handshake_error)
      ?on_done_with_internal_buffer
      ~authorize
      ~krb_mode
      (handle_client_with_anon
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
        ?on_done_with_internal_buffer
        ~authorize
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
      ~on_handler_error:(handshake_handler_for_rpc on_handshake_error)
      ?on_done_with_internal_buffer
      ~authorize
      ~krb_mode
      ~where_to_listen
      (handle_client_with_anon
         ?heartbeat_config
         ?handshake_timeout
         initial_connection_state
         implementations
       |> Staged.unstage)
  ;;

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
        ?on_credential_forwarding_request
        ?on_done_with_internal_buffer
        ?krb_mode
        ~authorize
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
      ?on_credential_forwarding_request
      ?on_done_with_internal_buffer
      ?krb_mode
      ~authorize
      where_to_connect
    >>=? fun t ->
    Deferred.Or_error.try_with
      ~run:`Schedule
      (fun () -> f t)
    >>= fun result -> Rpc.Connection.close t >>| fun () -> result
  ;;
end

let%test_module "Ensure test mode works" =
  (module struct
    let serve
          ~implementations
          ~initial_connection_state
          ~where_to_listen
          ~krb_mode
          ~authorize
      =
      Connection.serve
        ~implementations
        ~initial_connection_state
        ~where_to_listen
        ~krb_mode
        ~authorize
        ()
    ;;

    let with_client ~authorize ~krb_mode where_to_connect f =
      Connection.with_client ~authorize ~krb_mode where_to_connect f
    ;;

    let%test_unit "Test mode works" =
      Kerberized_rpc_over_protocol.For_testing.ensure_test_mode_works ~serve ~with_client
    ;;
  end)
;;
