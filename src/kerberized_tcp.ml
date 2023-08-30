open Core
open Async
open Import
module Debug = Internal.Debug

type 'a with_krb_args =
  ?cred_cache:Cred_cache.t -> ?krb_mode:Mode.Client.t -> authorize:Authorize.t -> 'a

type 'a with_connect_args =
  (Socket.Address.Inet.t Tcp.Where_to_connect.t -> 'a) with_krb_args
  Tcp.Aliases.with_connect_options

module Client = struct
  module Internal = struct
    let create_backend ~socket:_ ~tcp_reader ~tcp_writer =
      Protocol_backend_async.create ~reader:tcp_reader ~writer:tcp_writer
    ;;

    let connect =
      Kerberized_tcp_over_protocol.Client.connect_and_handshake
        (module Async_protocol)
        ~create_backend
    ;;
  end

  let connect
    ?buffer_age_limit
    ?interrupt
    ?reader_buffer_size
    ?writer_buffer_size
    ?timeout
    ?time_source
    ?cred_cache
    ?krb_mode
    ~authorize
    where_to_connect
    =
    let%bind.Deferred.Or_error connection =
      Internal.connect
        ?buffer_age_limit
        ?interrupt
        ?reader_buffer_size
        ?writer_buffer_size
        ?timeout
        ?time_source
        ?cred_cache
        ?override_supported_versions:None
        ?krb_mode
        ~authorize
        where_to_connect
    in
    let%map kerberized_rw = Kerberized_rw.create connection in
    let server_principal = Async_protocol.Connection.peer_principal connection in
    Ok (kerberized_rw, { Server_principal.server_principal })
  ;;

  let with_connection
    ?buffer_age_limit
    ?interrupt
    ?reader_buffer_size
    ?writer_buffer_size
    ?timeout
    ?time_source
    ?cred_cache
    ?krb_mode
    ~authorize
    where_to_connect
    f
    =
    connect
      ?buffer_age_limit
      ?interrupt
      ?reader_buffer_size
      ?writer_buffer_size
      ?timeout
      ?time_source
      ?cred_cache
      ?krb_mode
      ~authorize
      where_to_connect
    >>=? fun (kerberized_rw, server_principal) ->
    Deferred.Or_error.try_with ~here:[%here] (fun () -> f kerberized_rw server_principal)
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

  module Internal = struct
    let handler_from_server_protocol
      ?on_kerberos_error
      ?on_handshake_error
      ?on_handler_error
      handle_client
      server_protocol
      peer
      reader
      writer
      =
      let backend_or_error = Protocol_backend_async.create ~reader ~writer in
      Kerberized_tcp_over_protocol.Server.handler_from_server_protocol
        ?on_kerberos_error
        ?on_handshake_error
        ?on_handler_error
        handle_client
        server_protocol
        peer
        backend_or_error
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
      Deferred.Or_error.try_with_join ~here:[%here] (fun () ->
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

    let krb_server_protocol
      ?override_supported_versions
      ?additional_magic_numbers
      ~authorize
      ~krb_mode
      ()
      =
      Kerberized_tcp_over_protocol.Server.krb_server_protocol
        (module Async_protocol)
        ?override_supported_versions
        ?additional_magic_numbers
        ~authorize
        ~krb_mode
        ()
    ;;

    module Krb_or_anon_conn = struct
      type t =
        | Krb of Async_protocol.Connection.t
        | Anon of (Reader.t * Writer.t)
    end

    let krb_or_anon_server_protocol ?override_supported_versions ~authorize ~krb_mode () =
      Kerberized_tcp_over_protocol.Server.krb_or_anon_server_protocol
        (module Protocol_backend_async)
        (module Async_protocol)
        ?override_supported_versions
        ~peek_protocol_version_header:(fun backend ->
          Protocol_backend_async.peek_bin_prot
            backend
            Protocol_version_header.any_magic_prefix)
        ~authorize
        ~krb_mode
        ()
      >>|? fun server_protocol ->
      let server_protocol ~peer backend =
        match%bind server_protocol ~peer backend with
        | Error error -> Deferred.Result.fail error
        | Ok (`Krb conn) -> Deferred.Result.return (Krb_or_anon_conn.Krb conn)
        | Ok `Anon ->
          Deferred.Result.return
            (Krb_or_anon_conn.Anon
               ( Protocol_backend_async.reader backend
               , Protocol_backend_async.writer backend ))
      in
      server_protocol
    ;;

    let create_handler
      ?additional_magic_numbers
      ?on_kerberos_error
      ?on_handshake_error
      ?on_handler_error
      ?override_supported_versions
      ~authorize
      ~krb_mode
      handle_client
      =
      krb_server_protocol
        ?override_supported_versions
        ?additional_magic_numbers
        ~authorize
        ~krb_mode
        ()
      >>|? fun server_protocol ->
      handler_from_server_protocol
        ?on_kerberos_error
        ?on_handshake_error
        ?on_handler_error
        handle_client
        server_protocol
    ;;

    let create_handler_with_anon
      ?on_kerberos_error
      ?on_handshake_error
      ?on_handler_error
      ?override_supported_versions
      ~authorize
      ~krb_mode
      handle_client
      =
      krb_or_anon_server_protocol ?override_supported_versions ~authorize ~krb_mode ()
      >>|? fun server_protocol ->
      handler_from_server_protocol
        ?on_kerberos_error
        ?on_handshake_error
        ?on_handler_error
        handle_client
        server_protocol
    ;;

    let create
      ?additional_magic_numbers
      ?max_connections
      ?backlog
      ?drop_incoming_connections
      ?buffer_age_limit
      ?on_kerberos_error
      ?on_handshake_error
      ?on_handler_error
      ?override_supported_versions
      ~authorize
      ~krb_mode
      where_to_listen
      handle_client
      =
      Debug.log_s (fun () ->
        [%message
          "Starting Kerberized server"
            (where_to_listen : Tcp.Where_to_listen.inet)
            (krb_mode : Mode.Server.t)]);
      krb_server_protocol
        ?override_supported_versions
        ?additional_magic_numbers
        ~authorize
        ~krb_mode
        ()
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

    let create_with_anon
      ?max_connections
      ?backlog
      ?drop_incoming_connections
      ?buffer_age_limit
      ?on_kerberos_error
      ?on_handshake_error
      ?on_handler_error
      ?override_supported_versions
      ~authorize
      ~krb_mode
      where_to_listen
      handle_client
      =
      krb_or_anon_server_protocol ?override_supported_versions ~authorize ~krb_mode ()
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
  end

  let create
    ?max_connections
    ?backlog
    ?drop_incoming_connections
    ?buffer_age_limit
    ?on_kerberos_error
    ?on_handshake_error
    ?on_handler_error
    ?override_supported_versions
    ~authorize
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
      ?override_supported_versions
      ~authorize
      ~krb_mode
      where_to_listen
      (fun addr connection ->
      Kerberized_rw.create connection
      >>= fun kerberized_rw ->
      let client_principal = Async_protocol.Connection.peer_principal connection in
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
  module Endpoint = Kerberized_tcp_over_protocol.Server.Endpoint
  include Client.Internal
end
