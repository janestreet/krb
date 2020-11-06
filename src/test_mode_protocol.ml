open! Core
open! Async

module type S = Test_mode_protocol_intf.S

module Header = struct
  type t = Protocol_version_header.t [@@deriving bin_io]

  let v1 =
    Protocol_version_header.create_exn ~protocol:Krb_test_mode ~supported_versions:[ 1 ]
  ;;
end

module Syn = struct
  type t = Principal.Stable.Name.V1.t [@@deriving bin_io]
end

module Ack = struct
  type t = unit Or_error.t [@@deriving bin_io]
end

module Make (Backend : Protocol_backend_intf.S) = struct
  module P = Protocol.Make (Backend)
  module Connection = P.Connection

  let syn ~acting_as backend this_principal =
    Backend.write_bin_prot backend Header.bin_writer_t Header.v1;
    match%bind Backend.read_bin_prot backend Header.bin_reader_t with
    | `Eof ->
      raise_s
        [%message
          "failed reading [Test_mode_protocol.Header]"
            (acting_as : _ On_connection.Acting_as.t)]
    | `Ok peer ->
      (match
         Protocol_version_header.negotiate ~allow_legacy_peer:false ~us:Header.v1 ~peer
         |> ok_exn
       with
       | 1 ->
         Backend.write_bin_prot backend Syn.bin_writer_t this_principal;
         (match%bind Backend.read_bin_prot backend Syn.bin_reader_t with
          | `Eof ->
            raise_s
              [%message
                "failed reading [Test_mode_protocol.Syn]"
                  (acting_as : _ On_connection.Acting_as.t)]
          | `Ok that_principal -> return that_principal)
       | _ -> failwith "Negotiated unknown version number")
  ;;

  let ack ~acting_as backend v =
    Backend.write_bin_prot backend Ack.bin_writer_t v;
    match%bind Backend.read_bin_prot backend Ack.bin_reader_t with
    | `Eof ->
      raise_s
        [%message
          "failed reading [Test_mode_protocol.Ack]"
            (acting_as : _ On_connection.Acting_as.t)]
    | `Ok ack -> return ack
  ;;

  let handshake
        ?(on_connection = fun _ _ -> `Accept)
        ~acting_as
        ~principal
        ~peer_addr
        backend
    =
    syn ~acting_as backend principal
    >>= fun other_principal ->
    let on_connection_result =
      On_connection.run
        ~f:on_connection
        ~acting_as
        ~peer_address:peer_addr
        other_principal
    in
    ack ~acting_as backend on_connection_result
    >>|? fun () ->
    let conn =
      Connection.create_for_test_mode
        ~backend
        ~conn_type:Auth
        ~my_principal:principal
        ~peer_principal:other_principal
    in
    conn, on_connection_result
  ;;

  module Client = struct
    let handshake ?on_connection ~principal ~server_addr =
      handshake ?on_connection ~acting_as:Client ~principal ~peer_addr:server_addr
    ;;
  end

  module Server = struct
    let serve_exn ?on_connection ~principal ~peer_addr backend =
      handshake ?on_connection ~acting_as:Server ~principal ~peer_addr backend
      >>| function
      | Error e -> Error (`Krb_error e)
      | Ok ((_ : Connection.t), Error (_ : Error.t)) -> Error `Rejected_client
      | Ok (conn, Ok ()) -> Ok conn
    ;;

    let serve ?on_connection ~principal ~client_addr backend =
      Deferred.Or_error.try_with
        ~run:
          `Schedule
        ~rest:`Log
        (fun () -> serve_exn ?on_connection ~principal ~peer_addr:client_addr backend)
      >>| function
      | Ok result -> result
      | Error e -> Error (`Handshake_error e)
    ;;
  end
end

include Make (Protocol_backend_async)

module Client = struct
  include Client

  let close_connection_via_reader_and_writer r w =
    Writer.close w ~force_close:(Clock.after (sec 30.)) >>= fun () -> Reader.close r
  ;;

  let connect_exn
        ?buffer_age_limit
        ?interrupt
        ?reader_buffer_size
        ?writer_buffer_size
        ?timeout
        ?on_connection
        ~principal
        where_to_connect
    =
    Tcp.connect
      ?timeout
      ?buffer_age_limit
      ?interrupt
      ?reader_buffer_size
      ?writer_buffer_size
      where_to_connect
    >>= fun (sock, reader, writer) ->
    return (Protocol_backend_async.create ~reader ~writer)
    >>=? fun backend ->
    Deferred.Or_error.try_with_join
      ~run:
        `Schedule
      ~rest:`Log
      (fun () ->
         let server_addr = Socket.getpeername sock in
         handshake ?on_connection ~principal ~server_addr backend)
    >>= function
    | Error e | Ok ((_ : Protocol.Connection.t), Error e) ->
      close_connection_via_reader_and_writer reader writer >>= fun () -> return (Error e)
    | Ok (conn, Ok ()) -> Deferred.Or_error.return conn
  ;;

  let connect
        ?buffer_age_limit
        ?interrupt
        ?reader_buffer_size
        ?writer_buffer_size
        ?timeout
        ?on_connection
        ~principal
        where_to_connect
    =
    Deferred.Or_error.try_with_join
      ~run:
        `Schedule
      ~rest:`Log
      (fun () ->
         connect_exn
           ?buffer_age_limit
           ?interrupt
           ?reader_buffer_size
           ?writer_buffer_size
           ?timeout
           ?on_connection
           ~principal
           where_to_connect)
  ;;
end

module Server = struct
  include Server

  let serve ?on_connection ~principal ~client_addr reader writer =
    match Protocol_backend_async.create ~reader ~writer with
    | Error err -> return (Error (`Krb_error err))
    | Ok backend -> serve ?on_connection ~principal ~client_addr backend
  ;;
end
