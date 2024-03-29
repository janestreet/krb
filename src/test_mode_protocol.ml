open! Core
open! Async
include Test_mode_protocol_intf

module Header = struct
  type t = Protocol_version_header.t [@@deriving bin_io]

  let v1 =
    Protocol_version_header.create_exn
      ()
      ~protocol:Krb_test_mode
      ~supported_versions:[ 1 ]
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
            (acting_as : Authorizer.Acting_as.t)]
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
                  (acting_as : Authorizer.Acting_as.t)]
          | `Ok that_principal -> return that_principal)
       | _ -> failwith "Negotiated unknown version number")
  ;;

  let ack_exn ~acting_as backend v =
    Backend.write_bin_prot_exn backend Ack.bin_writer_t v;
    match%bind Backend.read_bin_prot backend Ack.bin_reader_t with
    | `Eof ->
      raise_s
        [%message
          "failed reading [Test_mode_protocol.Ack]" (acting_as : Authorizer.Acting_as.t)]
    | `Ok ack -> return ack
  ;;

  let handshake_exn ~authorize ~acting_as ~principal ~peer_addr backend =
    (* Attempting to get the realm using [Realm.default ()] or any function that
       relies on the [Context_sequencer] causes issues with the netkit simulator
       due to how async is handled ([Netkit_simulator.wait] in [netkit_krb_tests.ml]).

       For now we have a fixed realm which should be fine in test environments.
       A new version of this protocol will have to be minted for cross-realm support.
    *)
    let realm = Krb_internal_public.Config.pre_v5_assumed_realm in
    let my_principal = Principal.Name.with_realm ~realm principal in
    syn_exn ~acting_as backend principal
    >>| Principal.Name.with_realm ~realm
    >>= fun other_principal ->
    Authorizer.run
      ~authorize
      ~acting_as
      ~my_principal
      ~peer_address:peer_addr
      ~peer_principal:other_principal
    >>= fun authorize_result ->
    ack_exn ~acting_as backend authorize_result
    >>|? fun () ->
    let conn =
      Connection.create_for_test_mode
        ~backend
        ~conn_type:Auth
        ~my_principal
        ~peer_principal:other_principal
    in
    conn, authorize_result
  ;;

  module Client = struct
    let handshake ~authorize ~principal ~server_addr backend =
      Deferred.Or_error.try_with_join ~here:[%here] (fun () ->
        handshake_exn
          ~authorize
          ~acting_as:Client
          ~principal
          ~peer_addr:server_addr
          backend)
    ;;
  end

  module Server = struct
    let serve_exn ~authorize ~principal ~peer_addr backend =
      handshake_exn ~authorize ~acting_as:Server ~principal ~peer_addr backend
      >>| function
      | Error e -> Error (`Krb_error e)
      | Ok ((_ : Connection.t), Error (_ : Error.t)) -> Error `Rejected_client
      | Ok (conn, Ok ()) -> Ok conn
    ;;

    let serve ~authorize ~principal ~client_addr backend =
      Deferred.Or_error.try_with ~run:`Schedule ~here:[%here] (fun () ->
        serve_exn ~authorize ~principal ~peer_addr:client_addr backend)
      >>| function
      | Ok result -> result
      | Error e ->
        Error (`Handshake_error (Handshake_error.of_error ~kind:Unexpected_exception e))
    ;;
  end
end
