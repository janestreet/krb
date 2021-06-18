open! Core
open! Async
open! Import

module Client = struct
  let handshake'
        (type backend conn)
        (module Protocol : Protocol_with_test_mode_intf.S
          with type protocol_backend = backend
           and type Connection.t = conn)
        ?override_supported_versions
        ~authorize
        ~backend
        ~krb_mode_with_client_cred_cache
        socket
    =
    let open Deferred.Or_error.Let_syntax in
    let peer = Socket.getpeername socket in
    match krb_mode_with_client_cred_cache with
    | `Test_with_principal principal ->
      let%bind connection, authorize_result =
        Protocol.Test_mode.Client.handshake
          ~authorize
          ~principal
          ~server_addr:peer
          backend
      in
      let%map () = Deferred.return authorize_result in
      connection
    | `Kerberized (accepted_conn_types, client_cred_cache) ->
      Protocol.Client.handshake
        ?override_supported_versions
        ~authorize
        ~client_cred_cache
        ~accepted_conn_types
        ~peer
        backend
  ;;

  let handshake
        (type backend conn)
        (module Protocol : Protocol_with_test_mode_intf.S
          with type protocol_backend = backend
           and type Connection.t = conn)
        ~create_backend
        ?override_supported_versions
        ~authorize
        ~krb_mode_with_client_cred_cache
        ~socket
        ~tcp_reader
        ~tcp_writer
    =
    let open Deferred.Or_error.Let_syntax in
    let%bind backend =
      create_backend ~socket ~tcp_reader ~tcp_writer |> Deferred.return
    in
    handshake'
      (module Protocol)
      ?override_supported_versions
      ~authorize
      ~backend
      ~krb_mode_with_client_cred_cache
      socket
  ;;

  let handshake_sock
        (type backend conn)
        (module Protocol : Protocol_with_test_mode_intf.S
          with type protocol_backend = backend
           and type Connection.t = conn)
        ~create_backend
        ?override_supported_versions
        ~authorize
        ~krb_mode_with_client_cred_cache
        ~socket
    =
    let open Deferred.Or_error.Let_syntax in
    let%bind backend = create_backend ~socket |> Deferred.return in
    handshake'
      (module Protocol)
      ?override_supported_versions
      ~authorize
      ~backend
      ~krb_mode_with_client_cred_cache
      socket
  ;;

  let krb_mode_with_client_cred_cache ?cred_cache krb_mode =
    let open Deferred.Or_error.Let_syntax in
    match (krb_mode : Mode.Client.t) with
    | Test_with_principal principal -> return (`Test_with_principal principal)
    | Kerberized accepted_conn_types ->
      let%bind client_cred_cache =
        match cred_cache with
        | None -> Client_cred_cache.in_memory ()
        | Some cred_cache -> Client_cred_cache.of_cred_cache cred_cache
      in
      return (`Kerberized (accepted_conn_types, client_cred_cache))
  ;;

  let connect_and_handshake
        (type backend conn)
        (module Backend_protocol : Protocol_with_test_mode_intf.S
          with type protocol_backend = backend
           and type Connection.t = conn)
        ~create_backend
        ?buffer_age_limit
        ?interrupt
        ?reader_buffer_size
        ?writer_buffer_size
        ?timeout
        ?time_source
        ?override_supported_versions
        ?cred_cache
        ~authorize
        ~krb_mode
        where_to_connect
    =
    (* we have to do this logic upfront so that we don't try to connect if there is
       any error while creating the client cred cache. *)
    let open Deferred.Or_error.Let_syntax in
    let%bind krb_mode_with_client_cred_cache =
      krb_mode_with_client_cred_cache ?cred_cache krb_mode
    in
    Tcp_connect.connect_and_handshake
      ?buffer_age_limit
      ?interrupt
      ?reader_buffer_size
      ?writer_buffer_size
      ?timeout
      ?time_source
      where_to_connect
      ~handshake:
        (handshake
           (module Backend_protocol)
           ~create_backend
           ?override_supported_versions
           ~authorize
           ~krb_mode_with_client_cred_cache)
  ;;

  let connect_sock_and_handshake
        (type backend conn)
        (module Backend_protocol : Protocol_with_test_mode_intf.S
          with type protocol_backend = backend
           and type Connection.t = conn)
        ~create_backend
        ?interrupt
        ?timeout
        ?override_supported_versions
        ?cred_cache
        ~authorize
        ~krb_mode
        where_to_connect
    =
    (* we have to do this logic upfront so that we don't try to connect if there is
       any error while creating the client cred cache. *)
    let open Deferred.Or_error.Let_syntax in
    let%bind krb_mode_with_client_cred_cache =
      krb_mode_with_client_cred_cache ?cred_cache krb_mode
    in
    Tcp_connect.connect_sock_and_handshake
      ?interrupt
      ?timeout
      where_to_connect
      ~handshake:
        (handshake_sock
           (module Backend_protocol)
           ~create_backend
           ?override_supported_versions
           ~authorize
           ~krb_mode_with_client_cred_cache)
  ;;
end

module Server = struct
  (* From a [key_source], get the server's principal and a function to get the encryption
     key *)
  module Endpoint = struct
    let from_keytab ~principal keytab_source =
      Keytab.load keytab_source
      >>=? fun keytab ->
      Keytab.validate keytab principal
      >>|? fun () ->
      let get_keytab () = Deferred.Or_error.return (`Service keytab) in
      principal, get_keytab
    ;;

    let from_tgt cred_cache =
      Internal.Cred_cache.get_cached_tgt cred_cache
      >>|? fun tgt ->
      let get_tgt () =
        Internal.Cred_cache.get_cached_tgt cred_cache
        >>|? fun tgt -> `User_to_user_via_tgt tgt
      in
      Internal.Credentials.client tgt, get_tgt
    ;;

    let create (key_source : Server_key_source.t) =
      let open Deferred.Or_error.Let_syntax in
      match key_source with
      | Tgt ->
        let%bind cred_cache = Cred_cache.default () in
        from_tgt cred_cache
      | Keytab (_, keytab_source) ->
        let%bind principal = Server_key_source.principal key_source in
        from_keytab ~principal keytab_source
    ;;
  end

  let handle_on_error ~monitor handle addr e =
    let exn = Error.to_exn e in
    try
      match handle with
      | `Ignore -> ()
      | `Raise -> raise exn
      | `Call f -> f addr exn
    with
    | exn -> Monitor.send_exn monitor exn
  ;;

  let write_to_log_global =
    `Call
      (fun remote_addr exn ->
         Log.Global.sexp
           ~level:`Error
           [%message "Kerberos error" (remote_addr : Socket.Address.Inet.t) (exn : Exn.t)])
  ;;

  let handler_from_server_protocol
        ?(on_kerberos_error = write_to_log_global)
        ?(on_handshake_error = `Ignore)
        ?(on_handler_error = `Raise)
        handle_client
        server_protocol
        peer
        backend_or_error
    =
    let monitor = Monitor.current () in
    Monitor.try_with_or_error
      ~rest:`Log
      (fun () ->
         let open Deferred.Result.Let_syntax in
         let%bind backend =
           match backend_or_error with
           | Ok backend -> return backend
           | Error error -> Deferred.Result.fail (`Krb_error error)
         in
         server_protocol ~peer backend)
    >>= function
    | Error e -> return (handle_on_error ~monitor on_kerberos_error peer e)
    | Ok (Error (`Krb_error e)) ->
      return (handle_on_error ~monitor on_kerberos_error peer e)
    | Ok (Error (`Handshake_error e)) ->
      return (handle_on_error ~monitor on_handshake_error peer e)
    | Ok (Error `Rejected_client) ->
      (* This can be logged in the servers [authorize] *)
      return ()
    | Ok (Ok connection) ->
      Monitor.try_with_or_error
        ~rest:`Log
        (fun () -> handle_client peer connection)
      >>= (function
        | Error e -> return (handle_on_error ~monitor on_handler_error peer e)
        | Ok () -> return ())
  ;;

  let krb_server_protocol
        (type backend conn)
        (module Protocol : Protocol_with_test_mode_intf.S
          with type protocol_backend = backend
           and type Connection.t = conn)
        ~authorize
        krb_mode
    =
    match (krb_mode : Mode.Server.t) with
    | Kerberized (key_source, accepted_conn_types) ->
      Endpoint.create key_source
      >>=? fun (principal, get_endpoint) ->
      let server_protocol ~peer backend =
        get_endpoint ()
        >>= function
        | Error e -> return (Error (`Krb_error e))
        | Ok endpoint ->
          Protocol.Server.handshake
            ~authorize
            ~accepted_conn_types
            ~principal
            endpoint
            ~peer
            backend
      in
      return (Ok server_protocol)
    | Test_with_principal principal ->
      let server_protocol ~peer backend =
        Protocol.Test_mode.Server.serve ~authorize ~principal ~client_addr:peer backend
      in
      return (Ok server_protocol)
  ;;

  let krb_or_anon_server_protocol
        (type backend conn)
        (module Backend : Protocol_backend_intf.S with type t = backend)
        (module Protocol : Protocol_with_test_mode_intf.S
          with type protocol_backend = backend
           and type Connection.t = conn)
        ~peek_protocol_version_header
        ~authorize
        krb_mode
    =
    let authorize_mapped = Authorize.krb_of_anon authorize in
    krb_server_protocol (module Protocol) ~authorize:authorize_mapped krb_mode
    >>=? fun krb_server_protocol ->
    let server_protocol ~peer backend =
      let%bind peek_result =
        Deferred.Or_error.try_with (fun () -> peek_protocol_version_header backend)
        >>| function
        | Error _ | Ok `Eof -> `Ok None
        | Ok `Not_enough_data -> `Not_enough_data
        | Ok (`Ok x) -> `Ok x
      in
      match peek_result with
      | `Not_enough_data ->
        return
          (Error
             (`Handshake_error
                (Error.of_string
                   "Not enough data written by the client to determine if it's kerberized")))
      | `Ok (Some Protocol_version_header.Known_protocol.Krb) | `Ok (Some Krb_test_mode)
        -> krb_server_protocol ~peer backend >>|? fun conn -> `Krb conn
      (* [None] is assumed to be an async rpc client here so that async rpc clients
         rolled prior to the addition of the magic number (c. 02-2017) will be able to
         connect. *)
      | `Ok (Some Rpc) | `Ok None ->
        let ok = Ok `Anon in
        (match Authorize.For_internal_use.Anon.authorize authorize peer None with
         | `Accept -> return ok
         | `Reject -> return (Error `Rejected_client))
    in
    Deferred.Result.return server_protocol
  ;;
end
