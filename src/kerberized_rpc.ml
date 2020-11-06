open Core
open Async
open Import
module Auth_context = Internal.Auth_context
module Transport = Kerberized_rpc_transport

let collect_errors writer_monitor ~f =
  choose
    [ choice (Monitor.detach_and_get_next_error writer_monitor) (fun e -> Error e)
    ; choice
        (try_with
           ~run:
             `Schedule
           ~rest:`Log
           ~name:"Rpc.Connection.collect_errors"
           f)
        Fn.id
    ]
;;

type 'a async_rpc_args =
  ?max_message_size:int
  -> ?handshake_timeout:Time.Span.t
  -> ?heartbeat_config:Rpc.Connection.Heartbeat_config.t
  -> 'a

module Request_forwarded_creds = struct
  type query = unit [@@deriving bin_io]
  type response = Auth_context.Krb_cred.t Or_error.t [@@deriving bin_io]

  let rpc =
    Rpc.Rpc.create
      ~name:"krb_request_forwarded_credentials"
      ~version:1
      ~bin_query
      ~bin_response
  ;;
end

module On_credential_forwarding_request = struct
  type t =
    | Deny
    | Allow_server_to_impersonate_me of { forwardable_tkt : bool }
end

module Connection = struct
  type t = Rpc.Connection.t

  let create_connection_collect_errors_and_close_exn
        ~implementations
        ~connection_state
        ~description
        ?handshake_timeout
        ?heartbeat_config
        (transport : Rpc.Transport.t)
    =
    let writer_monitor = Rpc.Transport.Writer.monitor transport.writer in
    collect_errors writer_monitor ~f:(fun () ->
      Async_rpc_kernel.Rpc.Connection.create
        ~implementations
        ~connection_state
        ~description
        ?handshake_timeout:
          (Option.map handshake_timeout ~f:Time_ns.Span.of_span_float_round_nearest)
        ?heartbeat_config
        transport
      >>= function
      | Error exn -> raise exn
      | Ok t -> Rpc.Connection.close_finished t)
    >>= fun result ->
    Rpc.Transport.close transport
    >>= fun () ->
    match result with
    | Error exn -> raise exn
    | Ok () -> return ()
  ;;

  let handle_client
        ?heartbeat_config
        ?handshake_timeout
        initial_connection_state
        implementations
    =
    Staged.stage (fun client_address (transport : Rpc.Transport.t) krb_ops ->
      let request_forwarded_creds rpc_connection () =
        Rpc.Rpc.dispatch Request_forwarded_creds.rpc rpc_connection ()
        >>| Or_error.join
        >>=? fun krb_cred ->
        Kerberized_rpc_transport.Internal.Tcp.Krb_ops.read_krb_cred krb_ops krb_cred
      in
      let client_principal =
        Kerberized_rpc_transport.Tcp.Krb_ops.peer_principal krb_ops
      in
      let description =
        let server_principal =
          Kerberized_rpc_transport.Tcp.Krb_ops.my_principal krb_ops
        in
        Info.create_s
          [%message
            "Kerberized RPC server"
              (client_address : Socket.Address.Inet.t)
              (client_principal : Principal.Name.t)
              (server_principal : Principal.Name.t)]
      in
      create_connection_collect_errors_and_close_exn
        ~implementations
        ~connection_state:(fun rpc_conn ->
          let client_identity =
            { Client_identity.client_principal
            ; request_forwarded_creds = request_forwarded_creds rpc_conn
            }
          in
          initial_connection_state client_identity client_address rpc_conn)
        ?handshake_timeout
        ~description
        ?heartbeat_config
        transport)
  ;;

  let serve
        ?max_message_size
        ?handshake_timeout
        ?heartbeat_config
        ?max_connections
        ?backlog
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
    let handle_krb_client =
      let initial_connection_state client_identity =
        initial_connection_state (Some client_identity)
      in
      handle_client
        ?heartbeat_config
        ?handshake_timeout
        initial_connection_state
        implementations
      |> Staged.unstage
    in
    let handle_rpc_client client_address =
      let connection_state conn = initial_connection_state None client_address conn in
      let description =
        Info.create_s
          [%message
            "Anon connection in Krb.Rpc.Connection.serve_with_anon"
              (client_address : Socket.Address.Inet.t)]
      in
      create_connection_collect_errors_and_close_exn
        ~implementations
        ~connection_state
        ~description
        ?handshake_timeout
        ?heartbeat_config
    in
    Staged.stage (fun client_address transport krb_ops ->
      match krb_ops with
      | Some krb_ops -> handle_krb_client client_address transport krb_ops
      | None -> handle_rpc_client client_address transport)
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
          ?(on_credential_forwarding_request =
            Fn.const On_credential_forwarding_request.Deny)
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
      >>=? fun (transport, krb_ops) ->
      let server_principal =
        Kerberized_rpc_transport.Tcp.Krb_ops.peer_principal krb_ops
      in
      let client_principal = Kerberized_rpc_transport.Tcp.Krb_ops.my_principal krb_ops in
      let description =
        match description with
        | Some i -> i
        | None ->
          let connected_to =
            (* We must guard this with [am_running_test] because the sexp_of function
               for [Tcp.Where_to_connect.inet] does not mask the port if it was
               constructed using [of_host_and_port] :/. *)
            match am_running_test with
            | true -> [%sexp "<omitted-in-test>"]
            | false -> [%sexp (where_to_connect : Tcp.Where_to_connect.inet)]
          in
          Info.create_s
            [%message
              "Kerberized RPC client"
                (connected_to : Sexp.t)
                (client_principal : Principal.Name.t)
                (server_principal : Principal.Name.t)]
      in
      let handshake_timeout = Time.diff finish_handshake_by (Time.now ()) in
      let implementations =
        Option.map implementations ~f:(fun f -> f { Server_principal.server_principal })
      in
      let forwarded_creds_implementation () =
        Option.some_if
          (Kerberized_rpc_transport.Internal.Tcp.Krb_ops.can_forward_creds krb_ops)
          (Rpc.Rpc.implement Request_forwarded_creds.rpc (fun _ () ->
             match
               on_credential_forwarding_request { Server_principal.server_principal }
             with
             | Allow_server_to_impersonate_me { forwardable_tkt } ->
               Kerberized_rpc_transport.Internal.Tcp.Krb_ops.make_krb_cred
                 krb_ops
                 ~forwardable:forwardable_tkt
             | Deny ->
               Deferred.Or_error.error_s
                 [%message
                   "Client denied request to forward credentials"
                     (client_principal : Principal.Name.t)
                     (server_principal : Principal.Name.t)]))
      in
      match (implementations : _ Rpc.Connection.Client_implementations.t option) with
      | None ->
        (match
           Rpc.Implementations.create
             ~implementations:(forwarded_creds_implementation () |> Option.to_list)
             ~on_unknown_rpc:`Continue
         with
         | Ok implementations ->
           Async_rpc_kernel.Rpc.Connection.create
             ~implementations
             ~connection_state:(const ())
             ~handshake_timeout:
               (Time_ns.Span.of_span_float_round_nearest handshake_timeout)
             ?heartbeat_config
             ~description
             transport
           >>| Or_error.of_exn_result
         | Error duplicate_impls ->
           Deferred.Or_error.error_s
             [%message
               "Unable to create client implementations"
                 (duplicate_impls
                  : [ `Duplicate_implementations of Rpc.Description.t list ])])
      | Some { implementations; connection_state } ->
        (match forwarded_creds_implementation () with
         | None -> Deferred.Or_error.return implementations
         | Some implementation ->
           Rpc.Implementations.add implementations implementation |> return)
        >>=? fun implementations ->
        Async_rpc_kernel.Rpc.Connection.create
          ~implementations
          ~connection_state
          ~handshake_timeout:(Time_ns.Span.of_span_float_round_nearest handshake_timeout)
          ?heartbeat_config
          ~description
          transport
        >>| Or_error.of_exn_result
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
    let test_async f =
      Thread_safe.block_on_async_exn (fun () ->
        Clock.with_timeout (sec 1.) (f ())
        >>| function
        | `Result x -> x
        | `Timeout -> failwith "Timeout.")
    ;;

    module Test_rpc = struct
      type query = { greeting : string } [@@deriving sexp, bin_io, compare]

      type response = Thank_you_very_much of Principal.Stable.Name.V1.t
      [@@deriving sexp, bin_io, compare]

      let test_query = { greeting = "hello, earthling" }
      let rpc = Rpc.Rpc.create ~name:"test-rpc" ~version:0 ~bin_query ~bin_response
    end

    let%test_unit "Test mode works" =
      test_async (fun () ->
        let implementations =
          match
            Rpc.Implementations.create
              ~on_unknown_rpc:`Raise
              ~implementations:
                [ Rpc.Rpc.implement Test_rpc.rpc (fun principal query ->
                    [%test_result: Test_rpc.query] query ~expect:Test_rpc.test_query;
                    return (Test_rpc.Thank_you_very_much principal))
                ]
          with
          | Ok t -> t
          | Error (`Duplicate_implementations _) ->
            failwith "impossible: only 1 implementation"
        in
        let service = Principal.Name.Service { service = "bogus"; hostname = "test" } in
        Connection.serve
          ~implementations
          ~initial_connection_state:(fun { client_principal; _ } _ _ ->
            client_principal)
          ~where_to_listen:Tcp.Where_to_listen.of_port_chosen_by_os
          ~krb_mode:(Test_with_principal service)
          ()
        >>= fun server ->
        let test_with_client ~krb_mode ~expect =
          let host = "127.0.0.1" in
          let port = Tcp.Server.listening_on (Or_error.ok_exn server) in
          Connection.with_client
            ~on_connection:(fun server_address { server_principal } ->
              if [%compare.equal: Principal.Name.t] service server_principal
              && [%compare.equal: Socket.Address.Inet.t]
                   server_address
                   (Socket.Address.Inet.create (Unix.Inet_addr.of_string host) ~port)
              then `Accept
              else `Reject)
            ~krb_mode
            (Tcp.Where_to_connect.of_host_and_port { host; port })
            (fun connection ->
               Rpc.Rpc.dispatch_exn Test_rpc.rpc connection Test_rpc.test_query
               >>| function
               | Thank_you_very_much principal ->
                 [%test_result: Principal.Name.t] principal ~expect)
          >>| ok_exn
        in
        let principal = Principal.Name.User "me" in
        test_with_client ~krb_mode:(Test_with_principal principal) ~expect:principal)
    ;;
  end)
;;
