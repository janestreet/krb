open Core
open Async
open Import
module Credentials = Internal.Credentials
module Debug = Internal.Debug
module Keytab_entry = Internal.Keytab_entry

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
    Credentials.client tgt, get_tgt
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

module Server_protocol = struct
  let test_mode ?on_connection principal =
    Staged.stage (fun ~peer reader writer ->
      Test_mode_protocol.Server.serve
        ?on_connection
        ~principal
        ~client_addr:peer
        reader
        writer)
  ;;

  let kerberized_mode ?on_connection ~accepted_conn_types ~principal get_endpoint =
    Staged.stage (fun ~peer reader writer ->
      get_endpoint ()
      >>= function
      | Error e -> return (Error (`Krb_error e))
      | Ok endpoint ->
        Protocol.Server.serve
          ?on_connection
          ~accepted_conn_types
          ~principal
          endpoint
          ~peer
          reader
          writer)
  ;;
end

type 'a with_krb_args =
  ?cred_cache:Cred_cache.t
  -> ?on_connection:(Socket.Address.Inet.t -> Server_principal.t -> [ `Accept | `Reject ])
  -> krb_mode:Mode.Client.t
  -> 'a

type 'a with_connect_args =
  (Socket.Address.Inet.t Tcp.Where_to_connect.t -> 'a) with_krb_args
    Tcp.with_connect_options

module Client = struct
  module Internal = struct
    let connect
          ?buffer_age_limit
          ?interrupt
          ?reader_buffer_size
          ?writer_buffer_size
          ?timeout
          ?override_supported_versions
          ?cred_cache
          ?on_connection
          ~krb_mode
          where_to_connect
      =
      match (krb_mode : Mode.Client.t) with
      | Kerberized accepted_conn_types ->
        (match cred_cache with
         | None -> Client_cred_cache.in_memory ()
         | Some cred_cache -> Client_cred_cache.of_cred_cache cred_cache)
        >>=? fun client_cred_cache ->
        Protocol.Client.connect
          ?buffer_age_limit
          ?interrupt
          ?reader_buffer_size
          ?writer_buffer_size
          ?timeout
          ?override_supported_versions
          ?on_connection
          ~client_cred_cache
          ~accepted_conn_types
          where_to_connect
      | Test_with_principal principal ->
        Test_mode_protocol.Client.connect
          ?buffer_age_limit
          ?interrupt
          ?reader_buffer_size
          ?writer_buffer_size
          ?timeout
          ?on_connection
          ~principal
          where_to_connect
    ;;
  end

  let connect
        ?buffer_age_limit
        ?interrupt
        ?reader_buffer_size
        ?writer_buffer_size
        ?timeout
        ?cred_cache
        ?on_connection
        ~krb_mode
        where_to_connect
    =
    Internal.connect
      ?buffer_age_limit
      ?interrupt
      ?reader_buffer_size
      ?writer_buffer_size
      ?timeout
      ?cred_cache
      ?override_supported_versions:None
      ?on_connection
      ~krb_mode
      where_to_connect
    >>=? fun connection ->
    Kerberized_rw.create connection
    >>| fun kerberized_rw ->
    let server_principal = Protocol.Connection.peer_principal connection in
    Ok (kerberized_rw, { Server_principal.server_principal })
  ;;

  let with_connection
        ?buffer_age_limit
        ?interrupt
        ?reader_buffer_size
        ?writer_buffer_size
        ?timeout
        ?cred_cache
        ?on_connection
        ~krb_mode
        where_to_connect
        f
    =
    connect
      ?buffer_age_limit
      ?interrupt
      ?reader_buffer_size
      ?writer_buffer_size
      ?timeout
      ?cred_cache
      ?on_connection
      ~krb_mode
      where_to_connect
    >>=? fun (kerberized_rw, server_principal) ->
    Deferred.Or_error.try_with
      ~run:
        `Schedule
      ~rest:`Log
      (fun () -> f kerberized_rw server_principal)
    >>= fun result ->
    Writer.close (Kerberized_rw.plaintext_writer kerberized_rw)
    >>= fun () ->
    Reader.close (Kerberized_rw.plaintext_reader kerberized_rw) >>| fun () -> result
  ;;
end

let connect = Client.connect
let with_connection = Client.with_connection

type 'a async_tcp_server_args =
  ?max_connections:int
  -> ?backlog:int
  -> ?drop_incoming_connections:bool
  -> ?buffer_age_limit:Writer.buffer_age_limit
  -> 'a

module Server = struct
  type ('a, 'b) t = ('a, 'b) Tcp.Server.t

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

  module Internal = struct
    let handler_from_server_protocol
          ?(on_kerberos_error = write_to_log_global)
          ?(on_handshake_error = `Ignore)
          ?(on_handler_error = `Raise)
          handle_client
          server_protocol
          peer
          reader
          writer
      =
      let monitor = Monitor.current () in
      Monitor.try_with_or_error
        ~rest:`Log
        (fun () -> server_protocol ~peer reader writer)
      >>= function
      | Error e -> return (handle_on_error ~monitor on_kerberos_error peer e)
      | Ok (Error (`Krb_error e)) ->
        return (handle_on_error ~monitor on_kerberos_error peer e)
      | Ok (Error (`Handshake_error e)) ->
        return (handle_on_error ~monitor on_handshake_error peer e)
      | Ok (Error `Rejected_client) ->
        (* This can be logged in the servers [on_connection] *)
        return ()
      | Ok (Ok connection) ->
        Monitor.try_with_or_error
          ~rest:`Log
          (fun () -> handle_client peer connection)
        >>= (function
          | Error e -> return (handle_on_error ~monitor on_handler_error peer e)
          | Ok () -> return ())
    ;;

    let create_from_server_protocol
          ?max_connections
          ?backlog
          ?drop_incoming_connections
          ?buffer_age_limit
          ?on_kerberos_error
          ?on_handshake_error
          ?on_handler_error
          where_to_listen
          handle_client
          server_protocol
      =
      Deferred.Or_error.try_with_join
        ~run:
          `Schedule
        ~rest:`Log
        (fun () ->
           Tcp.Server.create
             ?max_connections
             ?backlog
             ?drop_incoming_connections
             ?buffer_age_limit
             (* It is never safe to set this to `Raise, since this would allow a single
                misbehaving client to bring down the TCP server (via something as simple as
                "connection reset by peer" *)
             ~on_handler_error:`Ignore
             where_to_listen
             (handler_from_server_protocol
                ?on_kerberos_error
                ?on_handshake_error
                ?on_handler_error
                handle_client
                server_protocol)
           |> Deferred.ok)
    ;;

    let krb_server_protocol ?on_connection krb_mode =
      match (krb_mode : Mode.Server.t) with
      | Kerberized (key_source, accepted_conn_types) ->
        Endpoint.create key_source
        >>=? fun (principal, get_endpoint) ->
        let server_protocol =
          Server_protocol.kerberized_mode
            ?on_connection
            ~accepted_conn_types
            ~principal
            get_endpoint
          |> Staged.unstage
        in
        return (Ok server_protocol)
      | Test_with_principal principal ->
        let server_protocol =
          Server_protocol.test_mode ?on_connection principal |> Staged.unstage
        in
        return (Ok server_protocol)
    ;;

    let create_handler
          ?on_kerberos_error
          ?on_handshake_error
          ?on_handler_error
          ?on_connection
          ~krb_mode
          handle_client
      =
      krb_server_protocol ?on_connection krb_mode
      >>|? fun server_protocol ->
      handler_from_server_protocol
        ?on_kerberos_error
        ?on_handshake_error
        ?on_handler_error
        handle_client
        server_protocol
    ;;

    let create
          ?max_connections
          ?backlog
          ?drop_incoming_connections
          ?buffer_age_limit
          ?on_kerberos_error
          ?on_handshake_error
          ?on_handler_error
          ?on_connection
          ~krb_mode
          where_to_listen
          handle_client
      =
      Debug.log_s (fun () ->
        [%message
          "Starting Kerberized server"
            (where_to_listen : Tcp.Where_to_listen.inet)
            (krb_mode : Mode.Server.t)]);
      krb_server_protocol ?on_connection krb_mode
      >>=? fun server_protocol ->
      create_from_server_protocol
        ?max_connections
        ?backlog
        ?drop_incoming_connections
        ?buffer_age_limit
        ?on_kerberos_error
        ?on_handshake_error
        ?on_handler_error
        where_to_listen
        handle_client
        server_protocol
    ;;

    module Krb_or_anon_conn = struct
      type t =
        | Krb of Protocol.Connection.t
        | Anon of (Reader.t * Writer.t)
    end

    let create_with_anon
          ?max_connections
          ?backlog
          ?drop_incoming_connections
          ?buffer_age_limit
          ?on_kerberos_error
          ?on_handshake_error
          ?on_handler_error
          ?on_connection
          ~krb_mode
          where_to_listen
          handle_client
      =
      let on_connection_mapped =
        Option.map on_connection ~f:(fun on_connection addr principal ->
          on_connection addr (Some principal))
      in
      krb_server_protocol ?on_connection:on_connection_mapped krb_mode
      >>=? fun krb_server_protocol ->
      let server_protocol ~peer reader writer =
        Deferred.Or_error.try_with
          ~run:
            `Schedule
          ~rest:`Log
          (fun () -> Reader.peek_bin_prot reader Protocol_version_header.any_magic_prefix)
        >>| (function
          | Error _ | Ok `Eof -> None
          | Ok (`Ok x) -> x)
        >>= function
        | Some Krb | Some Krb_test_mode ->
          krb_server_protocol ~peer reader writer
          >>|? fun conn -> Krb_or_anon_conn.Krb conn
        (* [`Other] is assumed to be an async rpc client here so that async rpc clients
           rolled prior to the addition of the magic number (c. 02-2017) will be able to
           connect. *)
        | Some Rpc | None ->
          let ok = Ok (Krb_or_anon_conn.Anon (reader, writer)) in
          (match on_connection with
           | None -> return ok
           | Some on_connection ->
             (match on_connection peer None with
              | `Accept -> return ok
              | `Reject -> return (Error `Rejected_client)))
      in
      create_from_server_protocol
        ?max_connections
        ?backlog
        ?drop_incoming_connections
        ?buffer_age_limit
        ?on_kerberos_error
        ?on_handshake_error
        ?on_handler_error
        where_to_listen
        handle_client
        server_protocol
    ;;
  end

  let create
        ?max_connections
        ?backlog
        ?drop_incoming_connections
        ?buffer_age_limit
        ?on_kerberos_error
        ?on_handshake_error
        ?on_handler_error
        ?on_connection
        ~krb_mode
        where_to_listen
        handle_client
    =
    Internal.create
      ?max_connections
      ?backlog
      ?drop_incoming_connections
      ?buffer_age_limit
      ?on_kerberos_error
      ?on_handshake_error
      ?on_handler_error
      ?on_connection
      ~krb_mode
      where_to_listen
      (fun addr connection ->
         Kerberized_rw.create connection
         >>= fun kerberized_rw ->
         let client_principal = Protocol.Connection.peer_principal connection in
         handle_client
           { Client_principal.client_principal }
           addr
           (Kerberized_rw.plaintext_reader kerberized_rw)
           (Kerberized_rw.plaintext_writer kerberized_rw)
         >>= fun () ->
         (* Ensure that any writes to the plaintext writer are remotely flushed
            before terminating, otherwise [Tcp.Server] will close the kerberized
            writer before we've flushed to it. When dealing with
            [Kerberized_rw], we must be sure to close the plaintext writer
            before the connection's writer. *)
         Writer.close (Kerberized_rw.plaintext_writer kerberized_rw)
         >>= fun () -> Kerberized_rw.writer_closed_and_flushed kerberized_rw)
  ;;
end

module Internal = struct
  module Server = Server.Internal
  module Endpoint = Endpoint
  include Client.Internal
end
