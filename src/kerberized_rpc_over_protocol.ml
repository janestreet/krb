open! Core
open! Async
open! Import

let collect_errors writer_monitor ~f =
  choose
    [ choice (Monitor.detach_and_get_next_error writer_monitor) (fun e -> Error e)
    ; choice
        (try_with
           ~run:`Schedule
           ~name:"Rpc.Connection.collect_errors"
           f)
        Fn.id
    ]
;;

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
      (type conn)
      (module Connection : Protocol.Connection with type t = conn)
      ?heartbeat_config
      ?handshake_timeout
      initial_connection_state
      implementations
  =
  Staged.stage (fun client_address (transport : Rpc.Transport.t) conn ->
    let request_forwarded_creds rpc_connection () =
      Rpc.Rpc.dispatch Request_forwarded_creds_rpc.rpc rpc_connection ()
      >>| Or_error.join
      >>=? fun krb_cred -> Connection.read_krb_cred conn krb_cred
    in
    let client_principal = Connection.peer_principal conn in
    let description =
      let server_principal = Connection.my_principal conn in
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
          ; cross_realm_client_principal = Connection.Cross_realm.peer_principal conn
          ; request_forwarded_creds = request_forwarded_creds rpc_conn
          }
        in
        initial_connection_state client_identity client_address rpc_conn)
      ?handshake_timeout
      ~description
      ?heartbeat_config
      transport)
;;

let handle_client_with_anon
      (type conn)
      (module Connection : Protocol_intf.Connection with type t = conn)
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
      (module Connection)
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
  Staged.stage (fun client_address transport conn ->
    match conn with
    | Some conn -> handle_krb_client client_address transport conn
    | None -> handle_rpc_client client_address transport)
;;

let client
      (type conn)
      (module Connection : Protocol_intf.Connection with type t = conn)
      ?heartbeat_config
      ?implementations
      ?description
      ?(on_credential_forwarding_request = Fn.const On_credential_forwarding_request.Deny)
      ~finish_handshake_by
      where_to_connect
      transport
      conn
  =
  let server_principal = Connection.peer_principal conn in
  let client_principal = Connection.my_principal conn in
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
      (Connection.can_forward_creds conn)
      (Rpc.Rpc.implement Request_forwarded_creds_rpc.rpc (fun _ () ->
         match on_credential_forwarding_request { Server_principal.server_principal } with
         | Allow_server_to_impersonate_me { forwardable_tkt } ->
           Connection.make_krb_cred conn ~forwardable:forwardable_tkt
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
         ~handshake_timeout:(Time_ns.Span.of_span_float_round_nearest handshake_timeout)
         ?heartbeat_config
         ~description
         transport
       >>| Or_error.of_exn_result
     | Error duplicate_impls ->
       Deferred.Or_error.error_s
         [%message
           "Unable to create client implementations"
             (duplicate_impls : [ `Duplicate_implementations of Rpc.Description.t list ])])
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

module For_testing = struct
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

  let ensure_test_mode_works ~serve ~with_client =
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
      let client = Principal.Name.User "me" in
      let host = "127.0.0.1" in
      serve
        ~implementations
        ~initial_connection_state:(fun { Client_identity.client_principal; _ } _ _ ->
          client_principal)
        ~where_to_listen:Tcp.Where_to_listen.of_port_chosen_by_os
        ~krb_mode:(Mode.Test_with_principal service)
        ~authorize:
          (Authorize.create (fun (`Inet (client_host, _client_port)) client_principal ->
             if [%compare.equal: Principal.Name.t] client client_principal
             && [%compare.equal: Unix.Inet_addr.t]
                  client_host
                  (Unix.Inet_addr.of_string host)
             then `Accept
             else `Reject))
      >>= fun server ->
      let test_with_client ~krb_mode ~expect =
        let port = Tcp.Server.listening_on (Or_error.ok_exn server) in
        with_client
          ~authorize:
            (Authorize.create (fun server_address server_principal ->
               if [%compare.equal: Principal.Name.t] service server_principal
               && [%compare.equal: Socket.Address.Inet.t]
                    server_address
                    (Socket.Address.Inet.create (Unix.Inet_addr.of_string host) ~port)
               then `Accept
               else `Reject))
          ~krb_mode
          (Tcp.Where_to_connect.of_host_and_port { host; port })
          (fun connection ->
             Rpc.Rpc.dispatch_exn Test_rpc.rpc connection Test_rpc.test_query
             >>| function
             | Thank_you_very_much principal ->
               [%test_result: Principal.Name.t] principal ~expect)
        >>| ok_exn
      in
      test_with_client ~krb_mode:(Mode.Test_with_principal client) ~expect:client)
  ;;
end
