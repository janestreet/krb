open! Core
open! Async
include Test_mode_protocol_intf

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
  type protocol_backend = Backend.t

  module P = Protocol.Make (Backend)
  module Connection = P.Connection

  let syn_exn ~acting_as backend this_principal =
    Backend.write_bin_prot_exn backend Header.bin_writer_t Header.v1;
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
         Backend.write_bin_prot_exn backend Syn.bin_writer_t this_principal;
         (match%bind Backend.read_bin_prot backend Syn.bin_reader_t with
          | `Eof ->
            raise_s
              [%message
                "failed reading [Test_mode_protocol.Syn]"
                  (acting_as : _ On_connection.Acting_as.t)]
          | `Ok that_principal -> return that_principal)
       | _ -> failwith "Negotiated unknown version number")
  ;;

  let ack_exn ~acting_as backend v =
    Backend.write_bin_prot_exn backend Ack.bin_writer_t v;
    match%bind Backend.read_bin_prot backend Ack.bin_reader_t with
    | `Eof ->
      raise_s
        [%message
          "failed reading [Test_mode_protocol.Ack]"
            (acting_as : _ On_connection.Acting_as.t)]
    | `Ok ack -> return ack
  ;;

  let handshake_exn
        ?(on_connection = fun _ _ -> `Accept)
        ~acting_as
        ~principal
        ~peer_addr
        backend
    =
    syn_exn ~acting_as backend principal
    >>= fun other_principal ->
    let on_connection_result =
      On_connection.run
        ~f:on_connection
        ~acting_as
        ~peer_address:peer_addr
        other_principal
    in
    ack_exn ~acting_as backend on_connection_result
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
    let handshake ?on_connection ~principal ~server_addr backend =
      Deferred.Or_error.try_with_join ~run:`Now ~rest:`Log (fun () ->
        handshake_exn
          ?on_connection
          ~acting_as:Client
          ~principal
          ~peer_addr:server_addr
          backend)
    ;;
  end

  module Server = struct
    let serve_exn ?on_connection ~principal ~peer_addr backend =
      handshake_exn ?on_connection ~acting_as:Server ~principal ~peer_addr backend
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
