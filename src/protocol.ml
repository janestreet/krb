module Stable = struct
  open! Core.Core_stable

  module Header = struct
    module V1 = struct
      type t = Protocol_version_header.t [@@deriving bin_io, sexp]

      let versions = [ 1; 2; 3; 4 ]

      let value ?(override_supported_versions = versions) () =
        Protocol_version_header.create_exn
          ~protocol:Krb
          ~supported_versions:override_supported_versions
      ;;
    end
  end
end

open Core
open Async
open Import
module Auth_context = Internal.Auth_context
module Credentials = Internal.Credentials
module Flags = Internal.Krb_flags
module Debug = Internal.Debug

module type S = Protocol_intf.S

let krb_error = Deferred.Result.map_error ~f:(fun e -> `Krb_error e)
let handshake_error = Deferred.Result.map_error ~f:(fun e -> `Handshake_error e)
let supported_versions = Stable.Header.V1.versions

module Make (Backend : Protocol_backend_intf.S) = struct
  module Connection = struct
    type t =
      { backend : Backend.t
      ; auth_context : [ `Test_mode | `Prod of Auth_context.t ]
      ; conn_type : Conn_type.t
      ; forwarded_creds_auth_context : Auth_context.t option
      ; cred_cache : Internal.Cred_cache.t option
      ; my_principal : Principal.Name.t
      ; peer_principal : Principal.Name.t
      ; protocol_version : [ `Test_mode | `Versioned of int ]
      }
    [@@deriving fields]

    let create = Fields.create

    let create_for_test_mode =
      create
        ~auth_context:`Test_mode
        ~forwarded_creds_auth_context:None
        ~cred_cache:None
        ~protocol_version:`Test_mode
    ;;

    let create_no_forwarded_creds =
      create ~forwarded_creds_auth_context:None ~cred_cache:None
    ;;

    let create_client = create
    let create_server = create ~cred_cache:None

    let can_forward_creds t =
      Option.is_some t.cred_cache && Option.is_some t.forwarded_creds_auth_context
    ;;

    (* When a ticket is forwarded, the lifetime of the ticket is shortened to be the
       remaining lifetime of the ticket. For example, take a ticket with the following
       times:

       starttime: 10:00 AM
       endtime:   10:00 PM

       If this ticket is forwarded at 9:00 PM, the forwarded ticket will look like:

       starttime:  9:00 PM
       endtime:   10:00 PM

       Our client library attempts to renew credentials every 30 minutes, so we try to
       ensure our ticket has more lifetime than that. *)
    let try_to_ensure_tgt_is_valid_for_long_enough ~principal ~cred_cache =
      match%bind
        Tgt.ensure_valid
          ~valid_for_at_least:(Time.Span.of_hr 1.)
          ~keytab:User
          ~cred_cache
          principal
      with
      | Ok () -> return ()
      | Error error ->
        Log.Global.error_s
          [%message
            "Failed to renew credentials before forwarding. The ticket lifetime might be \
             short."
              (error : Error.t)];
        return ()
    ;;

    let make_krb_cred t ~forwardable =
      let open Deferred.Or_error.Let_syntax in
      let%bind client = Principal.create t.my_principal in
      match Option.both t.forwarded_creds_auth_context t.cred_cache with
      | Some (auth_context, cred_cache) ->
        let%bind () =
          try_to_ensure_tgt_is_valid_for_long_enough ~principal:t.my_principal ~cred_cache
          |> Deferred.ok
        in
        Auth_context.Client.make_krb_cred auth_context ~forwardable ~client cred_cache
      | None ->
        Deferred.Or_error.error_s
          [%message
            "Unable to make krb_cred for forwarded credentials."
              ~required_protocol_version:(`Versioned 4 : [ `Versioned of int ])
              ~negotiated_protocol_version:
                (t.protocol_version : [ `Test_mode | `Versioned of int ])]
    ;;

    let read_krb_cred t krb_cred =
      let open Deferred.Or_error.Let_syntax in
      let%bind cred_cache = Cred_cache.in_memory_for_principal t.peer_principal in
      match t.forwarded_creds_auth_context with
      | None ->
        Deferred.Or_error.error_s
          [%message
            "Unable to read krb_cred for forwarded credentials"
              ~required_protocol_version:(`Versioned 4 : [ `Versioned of int ])
              ~negotiated_protocol_version:
                (t.protocol_version : [ `Test_mode | `Versioned of int ])]
      | Some auth_context ->
        let%map () =
          Auth_context.Service.read_krb_cred_into_cred_cache
            auth_context
            krb_cred
            cred_cache
        in
        cred_cache
    ;;
  end

  let read_bin_prot' ~backend ~name bin_reader =
    Backend.read_bin_prot backend bin_reader
    >>| function
    | `Eof ->
      let error =
        Error.create_s
          [%message
            "Connection closed"
              ~while_reading:(name : string)
              ~connection:(Backend.info backend : Info.t)]
      in
      Error (`Handshake_error error)
    | `Ok res -> Ok res
  ;;

  let read_bin_prot ~backend ~name bin_reader =
    match%map read_bin_prot' ~backend ~name bin_reader with
    | Error (`Handshake_error e) -> Error e
    | Ok _ as res -> res
  ;;

  let read_field' ~conn_type ~auth_context ~backend ~name bin_reader =
    read_bin_prot' ~backend ~name Bigstring.Stable.V1.bin_reader_t
    >>=? fun res ->
    (match (conn_type : Conn_type.t) with
     | Auth -> Deferred.Or_error.return res
     | Safe -> Auth_context.Safe.decode auth_context (Bigsubstring.create res)
     | Priv -> Auth_context.Priv.decode auth_context (Bigsubstring.create res))
    |> krb_error
    >>=? fun buf ->
    Or_error.map (Bigstring.read_bin_prot buf bin_reader) ~f:fst
    |> return
    |> handshake_error
  ;;

  let read_field ~conn_type ~auth_context ~backend ~name bin_reader =
    match%map read_field' ~conn_type ~auth_context ~backend ~name bin_reader with
    | Error (`Krb_error e) | Error (`Handshake_error e) -> Error e
    | Ok _ as res -> res
  ;;

  let write_field' ~conn_type ~auth_context ~backend bin_writer value =
    let bs = Bin_prot.Utils.bin_dump ~header:true bin_writer value in
    (match (conn_type : Conn_type.t) with
     | Auth -> Deferred.Or_error.return bs
     | Safe -> Auth_context.Safe.encode auth_context (Bigsubstring.create bs)
     | Priv -> Auth_context.Priv.encode auth_context (Bigsubstring.create bs))
    |> krb_error
    >>|? fun x -> Backend.write_bin_prot backend Bigstring.Stable.V1.bin_writer_t x
  ;;

  let write_field ~conn_type ~auth_context ~backend bin_writer value =
    match%map write_field' ~conn_type ~auth_context ~backend bin_writer value with
    | Error (`Krb_error e) | Error (`Handshake_error e) -> Error e
    | Ok _ as res -> res
  ;;

  module Unstable = struct
    module Conn_type = Conn_type
    module Conn_type_preference = Conn_type_preference
  end

  open Stable
  module Conn_type = Conn_type.Stable
  module Conn_type_preference = Conn_type_preference.Stable

  let debug_log_connection_setup ~peer ~conn_type ~user_to_user ~acting_as =
    Debug.log_s (fun () ->
      [%message
        "Kerberized connection setup"
          (acting_as : [ `Client | `Server ])
          (peer : Socket.Address.Inet.t)
          (conn_type : Unstable.Conn_type.t)
          (user_to_user : bool)])
  ;;

  module V1 = struct
    (* Protocol overview:
       - Server writes [Header.Server.t]
       - Client reads [Header.Server.t], obtains ticket from KDC, sends [Header.Client.t]
       - Server reads [Header.Client.t], checks ticket. Sends error if this fails.
       - The connection is now authenticated
       - Both pick the maximum conn_type they both support
       - Both write an ACK (Server: unit Or_error.t, Client: unit) encrypted as per the agreed upon conn_type
       - Both read the ACK. If this succeeds, the connection is established
    *)
    module Ap_req = Auth_context.Ap_req
    module Auth_context = Auth_context.V1

    module Mode = struct
      type t =
        | Service
        | User_to_user of string
      [@@deriving bin_io, sexp]

      let is_user_to_user = function
        | Service -> false
        | User_to_user _ -> true
      ;;
    end

    module Header = struct
      module Server = struct
        type t =
          { accepted_conn_types : Conn_type.V1.t list
          ; principal : string
          ; endpoint : Mode.t
          }
        [@@deriving bin_io, fields]

        let write ~backend t = Backend.write_bin_prot backend bin_writer_t t
        let read ~backend = read_bin_prot ~backend ~name:"Server header" bin_reader_t
      end

      module Client = struct
        type t =
          { accepted_conn_types : Conn_type.V1.t list
          ; ap_request : Ap_req.t
          }
        [@@deriving bin_io, fields]

        let write ~backend t = Backend.write_bin_prot backend bin_writer_t t
        let read' ~backend = read_bin_prot' ~backend ~name:"Client header" bin_reader_t
      end
    end

    let handle_error ~backend tag result =
      Result.iter_error result ~f:(fun _ ->
        let e = Error.createf "This value will never be read" in
        Backend.write_bin_prot
          backend
          (Or_error.Stable.V2.bin_writer_t Unit.bin_writer_t)
          (Or_error.tag ~tag (Error e)));
      result
    ;;

    module Server = struct
      let do_setup ~accepted_conn_types ~on_connection ~principal ~peer endpoint backend =
        let principal_s = Principal.to_string principal in
        (match endpoint with
         | `Service keytab -> return (Ok (Mode.Service, `Keytab keytab))
         | `User_to_user_via_tgt tgt ->
           let endpoint = Mode.User_to_user (Credentials.ticket_string tgt) in
           Credentials.keyblock tgt
           |> krb_error
           >>|? fun keyblock -> endpoint, `User_to_user keyblock)
        >>=? fun (endpoint, authentication_key) ->
        let accepted_conn_types =
          Unstable.Conn_type_preference.to_set accepted_conn_types
        in
        let header =
          Header.Server.Fields.create
            ~accepted_conn_types:(Set.to_list accepted_conn_types)
            ~principal:principal_s
            ~endpoint
        in
        Header.Server.write ~backend header;
        Header.Client.read' ~backend
        >>| handle_error ~backend "failed to read client header"
        >>=? fun client_header ->
        Unstable.Conn_type.negotiate_strongest
          ~us:accepted_conn_types
          ~peer:
            (Header.Client.accepted_conn_types client_header
             |> Unstable.Conn_type.Set.of_list)
        |> return
        |> handshake_error
        >>=? fun conn_type ->
        debug_log_connection_setup
          ~peer
          ~conn_type
          ~user_to_user:(Mode.is_user_to_user endpoint)
          ~acting_as:`Server;
        Auth_context.Service.init
          principal
          authentication_key
          ~ap_req:(Header.Client.ap_request client_header)
          ~local_inet:(Backend.local_inet backend)
          ~remote_inet:(Backend.remote_inet backend)
        |> krb_error
        >>| handle_error ~backend "failed to initiate auth_context"
        >>=? fun (auth_context, client) ->
        let client_principal_name = Principal.name client in
        let on_connection_result =
          On_connection.run
            ~f:on_connection
            ~acting_as:Server
            ~peer_address:peer
            client_principal_name
        in
        write_field'
          ~conn_type
          ~auth_context
          ~backend
          (Or_error.Stable.V2.bin_writer_t Unit.bin_writer_t)
          on_connection_result
        >>=? fun () ->
        read_field' ~conn_type ~auth_context ~backend ~name:"Client ack" Unit.bin_reader_t
        >>|? fun () ->
        let conn =
          Connection.create_no_forwarded_creds
            ~conn_type
            ~auth_context:(`Prod auth_context)
            ~backend
            ~my_principal:(Principal.name principal)
            ~peer_principal:client_principal_name
            ~protocol_version:(`Versioned 1)
        in
        conn, on_connection_result
      ;;

      let setup ~accepted_conn_types ~on_connection ~principal ~peer endpoint backend =
        do_setup ~accepted_conn_types ~on_connection ~principal ~peer endpoint backend
        >>| function
        | Error _ as error -> error
        | Ok ((_ : Connection.t), Error (_ : Error.t)) -> Error `Rejected_client
        | Ok (conn, Ok ()) -> Ok conn
      ;;
    end

    module Client = struct
      let setup_client_context ~cred_cache ~backend server_header =
        let second_ticket, cred_cache_flags, client_context_flags =
          match Header.Server.endpoint server_header with
          | Service -> None, [], [ Flags.Ap_req.AP_OPTS_MUTUAL_REQUIRED ]
          | User_to_user tgt ->
            ( Some tgt
            , [ Flags.Get_credentials.KRB5_GC_USER_USER ]
            , [ AP_OPTS_USE_SESSION_KEY; AP_OPTS_MUTUAL_REQUIRED ] )
        in
        Internal.Cred_cache.principal cred_cache
        >>=? fun client ->
        Internal.Principal.of_string (Header.Server.principal server_header)
        >>=? fun server ->
        Credentials.create ?second_ticket ~client ~server ()
        >>=? fun credentials_request ->
        Internal.Cred_cache.get_credentials
          ~flags:cred_cache_flags
          cred_cache
          ~request:credentials_request
        >>=? fun credentials ->
        Auth_context.Client.init
          client_context_flags
          credentials
          ~local_inet:(Backend.local_inet backend)
          ~remote_inet:(Backend.remote_inet backend)
      ;;

      let setup ~cred_cache ~accepted_conn_types ~on_connection ~peer backend =
        Header.Server.read ~backend
        >>=? fun server_header ->
        let accepted_conn_types =
          Unstable.Conn_type_preference.to_set accepted_conn_types
        in
        Unstable.Conn_type.negotiate_strongest
          ~us:accepted_conn_types
          ~peer:
            (Header.Server.accepted_conn_types server_header
             |> Unstable.Conn_type.Set.of_list)
        |> return
        >>=? fun conn_type ->
        debug_log_connection_setup
          ~peer
          ~conn_type
          ~user_to_user:(Mode.is_user_to_user server_header.endpoint)
          ~acting_as:`Client;
        let server_principal_s = Header.Server.principal server_header in
        Internal.Principal.of_string server_principal_s
        >>=? fun server_principal ->
        let server_principal_name = Principal.name server_principal in
        On_connection.run
          ~f:on_connection
          ~acting_as:Client
          ~peer_address:peer
          server_principal_name
        |> return
        >>=? fun () ->
        setup_client_context ~cred_cache ~backend server_header
        >>=? fun (auth_context, ap_request) ->
        let client_header =
          Header.Client.Fields.create
            ~accepted_conn_types:(Set.to_list accepted_conn_types)
            ~ap_request
        in
        Header.Client.write ~backend client_header;
        write_field ~conn_type ~auth_context ~backend Unit.bin_writer_t ()
        >>=? fun () ->
        read_field
          ~conn_type
          ~auth_context
          ~backend
          ~name:"Server ack"
          (Or_error.Stable.V2.bin_reader_t Unit.bin_reader_t)
        >>| Or_error.join
        >>=? fun () ->
        Cred_cache.principal cred_cache
        >>|? fun my_principal ->
        Connection.create_no_forwarded_creds
          ~conn_type
          ~auth_context:(`Prod auth_context)
          ~backend
          ~my_principal
          ~peer_principal:server_principal_name
          ~protocol_version:(`Versioned 1)
      ;;
    end
  end

  module V2 = struct
    (* Protocol overview:
       - Server writes [Header.Server.t]
       - Client reads [Header.Server.t], obtains ticket from KDC, sends [Header.Client.t]
       - Server reads [Header.Client.t], checks ticket (establishing authenticity of client)
       - Server writes [Header.Ap_rep.t]
       - Client reads and verifies [Header.Ap_rep.t] (establishing authenticity of server)
       - The connection is now authenticated
       - Both pick the maximum conn_type they both support
       - Both write an ACK (Server: unit Or_error.t, Client: unit) encrypted as per the agreed upon conn_type
       - Both read the ACK. If this succeeds, the connection is established
    *)
    module Mode = struct
      type t =
        | Service
        | User_to_user of string
      [@@deriving bin_io, sexp]

      let is_user_to_user = function
        | Service -> false
        | User_to_user _ -> true
      ;;
    end

    module Header = struct
      module Server = struct
        type t =
          { accepted_conn_types : Conn_type_preference.V1.t
          ; principal : Principal.Stable.Name.V1.t
          ; endpoint : Mode.t
          }
        [@@deriving bin_io, fields, sexp]

        let write ~backend t = Backend.write_bin_prot backend bin_writer_t t
        let read ~backend = read_bin_prot ~backend ~name:"Server header" bin_reader_t
      end

      module Client = struct
        type t =
          { accepted_conn_types : Conn_type_preference.V1.t
          ; ap_request : Bigstring.Stable.V1.t
          }
        [@@deriving bin_io, fields, sexp]

        let write ~backend t = Backend.write_bin_prot backend bin_writer_t t
        let read' ~backend = read_bin_prot' ~backend ~name:"Client header" bin_reader_t
      end

      module Ap_rep = struct
        let write ~backend t =
          Backend.write_bin_prot backend Auth_context.Ap_rep.bin_writer_t t
        ;;

        let read ~backend =
          read_bin_prot ~backend ~name:"Ap_rep" Auth_context.Ap_rep.bin_reader_t
        ;;
      end
    end

    module Server = struct
      let do_setup ~accepted_conn_types ~on_connection ~principal ~peer endpoint backend =
        (match endpoint with
         | `Service keytab -> return (Ok (Mode.Service, `Keytab keytab))
         | `User_to_user_via_tgt tgt ->
           let endpoint = Mode.User_to_user (Credentials.ticket_string tgt) in
           Credentials.keyblock tgt
           |> krb_error
           >>|? fun keyblock -> endpoint, `User_to_user keyblock)
        >>=? fun (endpoint, authentication_key) ->
        let header =
          Header.Server.Fields.create
            ~accepted_conn_types
            ~principal:(Principal.name principal)
            ~endpoint
        in
        Header.Server.write ~backend header;
        Header.Client.read' ~backend
        >>=? fun client_header ->
        Unstable.Conn_type_preference.negotiate
          ~us:accepted_conn_types
          ~peer:(Header.Client.accepted_conn_types client_header)
        |> return
        |> handshake_error
        >>=? fun conn_type ->
        debug_log_connection_setup
          ~peer
          ~conn_type
          ~user_to_user:(Mode.is_user_to_user endpoint)
          ~acting_as:`Server;
        Auth_context.Service.init
          principal
          authentication_key
          ~ap_req:(Header.Client.ap_request client_header)
          ~local_inet:(Backend.local_inet backend)
          ~remote_inet:(Backend.remote_inet backend)
        |> krb_error
        >>=? fun (auth_context, client) ->
        Auth_context.Service.make_ap_rep auth_context
        |> krb_error
        >>=? fun ap_rep ->
        Header.Ap_rep.write ~backend ap_rep;
        let client_principal_name = Principal.name client in
        let on_connection_result =
          On_connection.run
            ~f:on_connection
            ~acting_as:Server
            ~peer_address:peer
            client_principal_name
        in
        (* These acks are probably not necessary at this point, but it is a good sanity
           check that both the client and server can encrypt/decrypt with the correct
           connection type. *)
        write_field'
          ~conn_type
          ~auth_context
          ~backend
          (Or_error.Stable.V2.bin_writer_t Unit.bin_writer_t)
          on_connection_result
        >>=? fun () ->
        read_field' ~conn_type ~auth_context ~backend ~name:"Client ack" Unit.bin_reader_t
        >>|? fun () ->
        let conn =
          Connection.create_no_forwarded_creds
            ~conn_type
            ~auth_context:(`Prod auth_context)
            ~backend
            ~my_principal:(Principal.name principal)
            ~peer_principal:client_principal_name
            ~protocol_version:(`Versioned 2)
        in
        conn, on_connection_result
      ;;

      let setup ~accepted_conn_types ~on_connection ~principal ~peer endpoint backend =
        do_setup ~accepted_conn_types ~on_connection ~principal ~peer endpoint backend
        >>| function
        | Error _ as error -> error
        | Ok ((_ : Connection.t), Error (_ : Error.t)) -> Error `Rejected_client
        | Ok (conn, Ok ()) -> Ok conn
      ;;
    end

    module Client = struct
      let setup_client_context ~cred_cache ~backend server_header =
        ignore (backend : Backend.t);
        let second_ticket, cred_cache_flags, client_context_flags =
          match Header.Server.endpoint server_header with
          | Service -> None, [], [ Flags.Ap_req.AP_OPTS_MUTUAL_REQUIRED ]
          | User_to_user tgt ->
            ( Some tgt
            , [ Flags.Get_credentials.KRB5_GC_USER_USER ]
            , [ AP_OPTS_USE_SESSION_KEY; AP_OPTS_MUTUAL_REQUIRED ] )
        in
        Internal.Cred_cache.principal cred_cache
        >>=? fun client ->
        Principal.create (Header.Server.principal server_header)
        >>=? fun server ->
        Credentials.create ?second_ticket ~client ~server ()
        >>=? fun credentials_request ->
        Internal.Cred_cache.get_credentials
          ~flags:cred_cache_flags
          cred_cache
          ~request:credentials_request
        >>=? fun credentials ->
        Auth_context.Client.init
          client_context_flags
          credentials
          ~local_inet:(Backend.local_inet backend)
          ~remote_inet:(Backend.remote_inet backend)
      ;;

      let setup ~cred_cache ~accepted_conn_types ~on_connection ~peer backend =
        Header.Server.read ~backend
        >>=? fun server_header ->
        Unstable.Conn_type_preference.negotiate
          ~us:accepted_conn_types
          ~peer:(Header.Server.accepted_conn_types server_header)
        |> return
        >>=? fun conn_type ->
        debug_log_connection_setup
          ~peer
          ~conn_type
          ~user_to_user:(Mode.is_user_to_user server_header.endpoint)
          ~acting_as:`Client;
        setup_client_context ~cred_cache ~backend server_header
        >>=? fun (auth_context, ap_request) ->
        let client_header =
          Header.Client.Fields.create ~accepted_conn_types ~ap_request
        in
        Header.Client.write ~backend client_header;
        Header.Ap_rep.read ~backend
        >>=? fun ap_rep ->
        Auth_context.Client.read_and_verify_ap_rep auth_context ~ap_rep
        >>=? fun () ->
        (* Check the server principal after receiving the [ap_rep]. Otherwise, we can't
           trust the principal if the connection type is [Auth]. *)
        let server_principal_name = Header.Server.principal server_header in
        On_connection.run
          ~f:on_connection
          ~acting_as:Client
          ~peer_address:peer
          server_principal_name
        |> return
        >>=? fun () ->
        write_field ~conn_type ~auth_context ~backend Unit.bin_writer_t ()
        >>=? fun () ->
        read_field
          ~conn_type
          ~auth_context
          ~backend
          ~name:"Server ack"
          (Or_error.Stable.V2.bin_reader_t Unit.bin_reader_t)
        >>| Or_error.join
        >>=? fun () ->
        Cred_cache.principal cred_cache
        >>|? fun my_principal ->
        Connection.create_no_forwarded_creds
          ~conn_type
          ~auth_context:(`Prod auth_context)
          ~backend
          ~my_principal
          ~peer_principal:server_principal_name
          ~protocol_version:(`Versioned 2)
      ;;
    end
  end

  module V3 = struct
    (* Protocol overview:
       - Server writes [Header.Server.t]
       - Client reads [Header.Server.t], obtains ticket from KDC, sends [Header.Client.t]
       - Server reads [Header.Client.t], checks ticket (establishing authenticity of client)
       - Server writes [Header.Ap_rep.t]
       - Client reads and verifies [Header.Ap_rep.t] (establishing authenticity of server)
       - The connection is now authenticated
       - Both pick the maximum conn_type they both support
       - Both write an ACK (Server: unit Or_error.t, Client: unit) encrypted as per the
         agreed upon conn_type
       - Both read the ACK.
       - If client's header said it was going to send a KRB-CRED message and the server's
         header said it was going to accept it, then client writes it and server reads it
       - If this all succeeds, the connection is established
    *)
    module Mode = struct
      type t =
        | Service
        | User_to_user of string
      [@@deriving bin_io, sexp]

      let is_user_to_user = function
        | Service -> false
        | User_to_user _ -> true
      ;;
    end

    let this_version = 3

    module Header = struct
      module Server = struct
        type t =
          { accepted_conn_types : Conn_type_preference.V1.t
          ; principal : Principal.Stable.Name.V1.t
          ; endpoint : Mode.t
          ; wants_forwarded_creds : bool
          }
        [@@deriving bin_io, fields, sexp]

        let write ~backend t = Backend.write_bin_prot backend bin_writer_t t
        let read ~backend = read_bin_prot ~backend ~name:"Server header" bin_reader_t
      end

      module Client = struct
        type t =
          { accepted_conn_types : Conn_type_preference.V1.t
          ; ap_request : Bigstring.Stable.V1.t
          ; forward_credentials_if_requested : bool
          }
        [@@deriving bin_io, fields, sexp]

        let write ~backend t = Backend.write_bin_prot backend bin_writer_t t
        let read' ~backend = read_bin_prot' ~backend ~name:"Client header" bin_reader_t
      end

      module Ap_rep = struct
        let write ~backend t =
          Backend.write_bin_prot backend Auth_context.Ap_rep.bin_writer_t t
        ;;

        let read ~backend =
          read_bin_prot ~backend ~name:"Ap_rep" Auth_context.Ap_rep.bin_reader_t
        ;;
      end
    end

    module Server = struct
      let do_setup
            ~accepted_conn_types
            ~on_connection
            ~principal
            ~wants_forwarded_creds
            ~peer
            endpoint
            backend
        =
        (match endpoint with
         | `Service keytab -> return (Ok (Mode.Service, `Keytab keytab))
         | `User_to_user_via_tgt tgt ->
           let endpoint = Mode.User_to_user (Credentials.ticket_string tgt) in
           Credentials.keyblock tgt
           |> krb_error
           >>|? fun keyblock -> endpoint, `User_to_user keyblock)
        >>=? fun (endpoint, authentication_key) ->
        let header =
          Header.Server.Fields.create
            ~accepted_conn_types
            ~principal:(Principal.name principal)
            ~endpoint
            ~wants_forwarded_creds
        in
        Header.Server.write ~backend header;
        Header.Client.read' ~backend
        >>=? fun client_header ->
        Unstable.Conn_type_preference.negotiate
          ~us:accepted_conn_types
          ~peer:(Header.Client.accepted_conn_types client_header)
        |> return
        |> handshake_error
        >>=? fun conn_type ->
        debug_log_connection_setup
          ~peer
          ~conn_type
          ~user_to_user:(Mode.is_user_to_user endpoint)
          ~acting_as:`Server;
        Auth_context.Service.init
          principal
          authentication_key
          ~ap_req:(Header.Client.ap_request client_header)
          ~local_inet:(Backend.local_inet backend)
          ~remote_inet:(Backend.remote_inet backend)
        |> krb_error
        >>=? fun (auth_context, client) ->
        Auth_context.Service.make_ap_rep auth_context
        |> krb_error
        >>=? fun ap_rep ->
        Header.Ap_rep.write ~backend ap_rep;
        let client_principal_name = Principal.name client in
        let on_connection_result =
          On_connection.run
            ~f:on_connection
            ~acting_as:Server
            ~peer_address:peer
            client_principal_name
        in
        (* These acks are probably not necessary at this point, but it is a good sanity
           check that both the client and server can encrypt/decrypt with the correct
           connection type. *)
        write_field'
          ~conn_type
          ~auth_context
          ~backend
          (Or_error.Stable.V2.bin_writer_t Unit.bin_writer_t)
          on_connection_result
        >>=? fun () ->
        read_field' ~conn_type ~auth_context ~backend ~name:"Client ack" Unit.bin_reader_t
        >>=? fun () ->
        Deferred.Result.Let_syntax.(
          if client_header.forward_credentials_if_requested && wants_forwarded_creds
          then (
            let%bind krb_cred =
              read_bin_prot' ~backend ~name:"KRB-CRED" Auth_context.Krb_cred.bin_reader_t
            in
            let%bind cred_cache =
              Cred_cache.in_memory_for_principal client_principal_name |> krb_error
            in
            let%map () =
              Auth_context.Service.read_krb_cred_into_cred_cache
                auth_context
                krb_cred
                cred_cache
              |> krb_error
            in
            Some cred_cache)
          else return None)
        >>|? fun client_creds ->
        (* [wants_forwarded_creds] is always passed as [false]. This simplifies the
           interface by breaking backwards compatibility with forwarding in V3 (i.e. there's
           no way for a connection with v3 on one end/v4 on the other to forward creds as
           the v4 side always says it doesn't want/won't forward them). *)
        if Option.is_some client_creds
        then
          failwith
            "BUG: Creds forwarding requested in krb V3 protocol, even though it was \
             disabled in code.";
        assert (Option.is_none client_creds);
        let conn =
          Connection.create_no_forwarded_creds
            ~conn_type
            ~auth_context:(`Prod auth_context)
            ~backend
            ~my_principal:(Principal.name principal)
            ~peer_principal:client_principal_name
            ~protocol_version:(`Versioned this_version)
        in
        conn, on_connection_result
      ;;

      let setup
            ~accepted_conn_types
            ~on_connection
            ~principal
            ~wants_forwarded_creds
            ~peer
            endpoint
            backend
        =
        do_setup
          ~accepted_conn_types
          ~on_connection
          ~principal
          ~wants_forwarded_creds
          ~peer
          endpoint
          backend
        >>| function
        | Error _ as error -> error
        | Ok ((_ : Connection.t), Error (_ : Error.t)) -> Error `Rejected_client
        | Ok (conn, Ok ()) -> Ok conn
      ;;
    end

    module Client = struct
      let setup_client_context ~cred_cache ~backend server_header =
        let second_ticket, cred_cache_flags, client_context_flags =
          match Header.Server.endpoint server_header with
          | Service -> None, [], [ Flags.Ap_req.AP_OPTS_MUTUAL_REQUIRED ]
          | User_to_user tgt ->
            ( Some tgt
            , [ Flags.Get_credentials.KRB5_GC_USER_USER ]
            , [ AP_OPTS_USE_SESSION_KEY; AP_OPTS_MUTUAL_REQUIRED ] )
        in
        Internal.Cred_cache.principal cred_cache
        >>=? fun client ->
        Principal.create (Header.Server.principal server_header)
        >>=? fun server ->
        Credentials.create ?second_ticket ~client ~server ()
        >>=? fun credentials_request ->
        Internal.Cred_cache.get_credentials
          ~flags:cred_cache_flags
          cred_cache
          ~request:credentials_request
        >>=? fun credentials ->
        Auth_context.Client.init
          client_context_flags
          credentials
          ~local_inet:(Backend.local_inet backend)
          ~remote_inet:(Backend.remote_inet backend)
      ;;

      let setup
            ~cred_cache
            ~accepted_conn_types
            ~on_connection
            ~forward_credentials_if_requested
            ~peer
            backend
        =
        Header.Server.read ~backend
        >>=? fun server_header ->
        Unstable.Conn_type_preference.negotiate
          ~us:accepted_conn_types
          ~peer:(Header.Server.accepted_conn_types server_header)
        |> return
        >>=? fun conn_type ->
        debug_log_connection_setup
          ~peer
          ~conn_type
          ~user_to_user:(Mode.is_user_to_user server_header.endpoint)
          ~acting_as:`Client;
        setup_client_context ~cred_cache ~backend server_header
        >>=? fun (auth_context, ap_request) ->
        let client_header =
          Header.Client.Fields.create
            ~accepted_conn_types
            ~ap_request
            ~forward_credentials_if_requested
        in
        Header.Client.write ~backend client_header;
        Header.Ap_rep.read ~backend
        >>=? fun ap_rep ->
        Auth_context.Client.read_and_verify_ap_rep auth_context ~ap_rep
        >>=? fun () ->
        (* Check the server principal after receiving the [ap_rep]. Otherwise, we can't
           trust the principal if the connection type is [Auth]. *)
        let server_principal_name = Header.Server.principal server_header in
        On_connection.run
          ~f:on_connection
          ~acting_as:Client
          ~peer_address:peer
          server_principal_name
        |> return
        >>=? fun () ->
        write_field ~conn_type ~auth_context ~backend Unit.bin_writer_t ()
        >>=? fun () ->
        read_field
          ~conn_type
          ~auth_context
          ~backend
          ~name:"Server ack"
          (Or_error.Stable.V2.bin_reader_t Unit.bin_reader_t)
        >>| Or_error.join
        >>=? fun () ->
        Deferred.Or_error.Let_syntax.(
          if forward_credentials_if_requested && server_header.wants_forwarded_creds
          then (
            let%bind client = Internal.Cred_cache.principal cred_cache in
            let%bind krb_cred =
              Auth_context.Client.make_krb_cred
                auth_context
                ~forwardable:false
                ~client
                cred_cache
            in
            (* All the sensitive bits of the KRB-CRED are encrypted, so we can send it
               safely over no matter the value of [conn_type]. *)
            Backend.write_bin_prot backend Auth_context.Krb_cred.bin_writer_t krb_cred;
            return ())
          else return ())
        >>=? fun () ->
        Cred_cache.principal cred_cache
        >>|? fun my_principal ->
        Connection.create_no_forwarded_creds
          ~conn_type
          ~auth_context:(`Prod auth_context)
          ~backend
          ~my_principal
          ~peer_principal:server_principal_name
          ~protocol_version:(`Versioned this_version)
      ;;
    end
  end

  (* This module improves on V3 by changing client credential forwarding to be dynamic,
     rather than something that needs to be established as a part of the initial protocol.
     In order to support this, a new auth context is created on both the client and
     server side because auth contexts use sequence numbers when encrypting/decrypting.
     Nested encryptions are not supported. *)
  module V4 = struct
    (* Protocol overview:
       - Server writes [Header.Server.t]
       - Client reads [Header.Server.t], obtains 2 tickets from KDC (one for each auth context),
         sends [Header.Client.t]
       - Server reads [Header.Client.t], checks tickets (establishing authenticity of client)
       - Server writes [Header.Ap_rep.t]
       - Client reads and verifies [Header.Ap_rep.t] (establishing authenticity of server)
       - The connection is now authenticated
       - Both pick the maximum conn_type they both support
       - Both write an ACK (Server: unit Or_error.t, Client: unit) encrypted as per the
         agreed upon conn_type
       - Both read the ACK.
       - If this all succeeds, the connection is established
    *)
    module Mode = struct
      type t =
        | Service
        | User_to_user of string
      [@@deriving bin_io, sexp]

      let is_user_to_user = function
        | Service -> false
        | User_to_user _ -> true
      ;;
    end

    let this_version = 4

    module Header = struct
      module Server = struct
        type t =
          { accepted_conn_types : Conn_type_preference.V1.t
          ; principal : Principal.Stable.Name.V1.t
          ; endpoint : Mode.t
          }
        [@@deriving bin_io, fields, sexp]

        let write ~backend t = Backend.write_bin_prot backend bin_writer_t t
        let read ~backend = read_bin_prot ~backend ~name:"Server header" bin_reader_t
      end

      module Client = struct
        type t =
          { accepted_conn_types : Conn_type_preference.V1.t
          ; ap_request : Bigstring.Stable.V1.t
          ; forwarded_creds_ap_request : Bigstring.Stable.V1.t
          }
        [@@deriving bin_io, fields, sexp]

        let write ~backend t = Backend.write_bin_prot backend bin_writer_t t
        let read' ~backend = read_bin_prot' ~backend ~name:"Client header" bin_reader_t
      end

      module Ap_rep = struct
        let write ~backend t =
          Backend.write_bin_prot backend Auth_context.Ap_rep.bin_writer_t t
        ;;

        let read ~backend =
          read_bin_prot ~backend ~name:"Ap_rep" Auth_context.Ap_rep.bin_reader_t
        ;;
      end
    end

    module Server = struct
      let do_setup ~accepted_conn_types ~on_connection ~principal ~peer endpoint backend =
        (match endpoint with
         | `Service keytab -> return (Ok (Mode.Service, `Keytab keytab))
         | `User_to_user_via_tgt tgt ->
           let endpoint = Mode.User_to_user (Credentials.ticket_string tgt) in
           Credentials.keyblock tgt
           |> krb_error
           >>|? fun keyblock -> endpoint, `User_to_user keyblock)
        >>=? fun (endpoint, authentication_key) ->
        let header =
          Header.Server.Fields.create
            ~accepted_conn_types
            ~principal:(Principal.name principal)
            ~endpoint
        in
        Header.Server.write ~backend header;
        Header.Client.read' ~backend
        >>=? fun client_header ->
        Unstable.Conn_type_preference.negotiate
          ~us:accepted_conn_types
          ~peer:(Header.Client.accepted_conn_types client_header)
        |> return
        |> handshake_error
        >>=? fun conn_type ->
        debug_log_connection_setup
          ~peer
          ~conn_type
          ~user_to_user:(Mode.is_user_to_user endpoint)
          ~acting_as:`Server;
        (let init_auth_context ap_req =
           Auth_context.Service.init
             principal
             authentication_key
             ~ap_req
             ~local_inet:(Backend.local_inet backend)
             ~remote_inet:(Backend.remote_inet backend)
         in
         init_auth_context (Header.Client.ap_request client_header)
         >>=? fun auth_context ->
         init_auth_context (Header.Client.forwarded_creds_ap_request client_header)
         >>|? fun forwarded_creds_auth_context ->
         auth_context, forwarded_creds_auth_context)
        |> krb_error
        >>=? fun ( (auth_context, client)
                 , (forwarded_creds_auth_context, forwarded_creds_client) ) ->
        (let client_s = Principal.to_string client in
         let forwarded_creds_client_s = Principal.to_string forwarded_creds_client in
         if String.equal client_s forwarded_creds_client_s
         then return (Ok ())
         else (
           let error =
             Error.create_s
               [%message
                 "Client principals in AP_REQs don't match"
                   ~client:(client_s : string)
                   ~forwarded_creds_client:(forwarded_creds_client_s : string)]
           in
           return (Error (`Krb_error error))))
        >>=? fun () ->
        Auth_context.Service.make_ap_rep auth_context
        |> krb_error
        >>=? fun ap_rep ->
        Header.Ap_rep.write ~backend ap_rep;
        let client_principal_name = Principal.name client in
        let on_connection_result =
          On_connection.run
            ~f:on_connection
            ~acting_as:Server
            ~peer_address:peer
            client_principal_name
        in
        (* These acks are probably not necessary at this point, but it is a good sanity
           check that both the client and server can encrypt/decrypt with the correct
           connection type. *)
        write_field'
          ~conn_type
          ~auth_context
          ~backend
          (Or_error.Stable.V2.bin_writer_t Unit.bin_writer_t)
          on_connection_result
        >>=? fun () ->
        read_field' ~conn_type ~auth_context ~backend ~name:"Client ack" Unit.bin_reader_t
        >>|? fun () ->
        let conn =
          Connection.create_server
            ~conn_type
            ~auth_context:(`Prod auth_context)
            ~forwarded_creds_auth_context:(Some forwarded_creds_auth_context)
            ~backend
            ~my_principal:(Principal.name principal)
            ~peer_principal:client_principal_name
            ~protocol_version:(`Versioned this_version)
        in
        conn, on_connection_result
      ;;

      let setup ~accepted_conn_types ~on_connection ~principal ~peer endpoint backend =
        do_setup ~accepted_conn_types ~on_connection ~principal ~peer endpoint backend
        >>| function
        | Error _ as error -> error
        | Ok ((_ : Connection.t), Error (_ : Error.t)) -> Error `Rejected_client
        | Ok (conn, Ok ()) -> Ok conn
      ;;
    end

    module Client = struct
      let setup_client_context ~client_cred_cache ~backend server_header =
        let second_ticket, cred_cache_flags, client_context_flags =
          match Header.Server.endpoint server_header with
          | Service -> None, [], [ Flags.Ap_req.AP_OPTS_MUTUAL_REQUIRED ]
          | User_to_user tgt ->
            ( Some tgt
            , [ Flags.Get_credentials.KRB5_GC_USER_USER ]
            , [ AP_OPTS_USE_SESSION_KEY; AP_OPTS_MUTUAL_REQUIRED ] )
        in
        let cred_cache = Client_cred_cache.cred_cache client_cred_cache in
        Internal.Cred_cache.principal cred_cache
        >>=? fun client ->
        Principal.create (Header.Server.principal server_header)
        >>=? fun server ->
        Credentials.create ?second_ticket ~client ~server ()
        >>=? fun credentials_request ->
        Client_cred_cache.get_credentials
          ~flags:cred_cache_flags
          client_cred_cache
          ~request:credentials_request
        >>=? fun (credentials, `Error_getting_creds_from_default_cache maybe_error) ->
        (match maybe_error with
         | None -> ()
         | Some error ->
           Log.Global.sexp
             ~level:`Info
             [%message
               "Failed to get credentials from default cache (succeeded with memory cache)"
                 (error : Error.t)
                 (client_cred_cache : Client_cred_cache.t)]);
        let init_auth_context () =
          Auth_context.Client.init
            client_context_flags
            credentials
            ~local_inet:(Backend.local_inet backend)
            ~remote_inet:(Backend.remote_inet backend)
        in
        init_auth_context ()
        >>=? fun (auth_context, ap_req) ->
        init_auth_context ()
        >>|? fun (forwarded_creds_auth_context, forwarded_creds_ap_req) ->
        auth_context, ap_req, forwarded_creds_auth_context, forwarded_creds_ap_req
      ;;

      let setup ~client_cred_cache ~accepted_conn_types ~on_connection ~peer backend =
        Header.Server.read ~backend
        >>=? fun server_header ->
        Unstable.Conn_type_preference.negotiate
          ~us:accepted_conn_types
          ~peer:(Header.Server.accepted_conn_types server_header)
        |> return
        >>=? fun conn_type ->
        debug_log_connection_setup
          ~peer
          ~conn_type
          ~user_to_user:(Mode.is_user_to_user server_header.endpoint)
          ~acting_as:`Client;
        setup_client_context ~client_cred_cache ~backend server_header
        >>=? fun ( auth_context
                 , ap_request
                 , forwarded_creds_auth_context
                 , forwarded_creds_ap_request ) ->
        let client_header =
          Header.Client.Fields.create
            ~accepted_conn_types
            ~ap_request
            ~forwarded_creds_ap_request
        in
        Header.Client.write ~backend client_header;
        Header.Ap_rep.read ~backend
        >>=? fun ap_rep ->
        Auth_context.Client.read_and_verify_ap_rep auth_context ~ap_rep
        >>=? fun () ->
        (* Check the server principal after receiving the [ap_rep]. Otherwise, we can't
           trust the principal if the connection type is [Auth]. *)
        let server_principal_name = Header.Server.principal server_header in
        On_connection.run
          ~f:on_connection
          ~acting_as:Client
          ~peer_address:peer
          server_principal_name
        |> return
        >>=? fun () ->
        write_field ~conn_type ~auth_context ~backend Unit.bin_writer_t ()
        >>=? fun () ->
        read_field
          ~conn_type
          ~auth_context
          ~backend
          ~name:"Server ack"
          (Or_error.Stable.V2.bin_reader_t Unit.bin_reader_t)
        >>| Or_error.join
        >>=? fun () ->
        let cred_cache = Client_cred_cache.cred_cache client_cred_cache in
        Cred_cache.principal cred_cache
        >>|? fun my_principal ->
        Connection.create_client
          ~conn_type
          ~auth_context:(`Prod auth_context)
          ~forwarded_creds_auth_context:(Some forwarded_creds_auth_context)
          ~backend
          ~cred_cache:(Some cred_cache)
          ~my_principal
          ~peer_principal:server_principal_name
          ~protocol_version:(`Versioned this_version)
      ;;
    end
  end

  let negotiate backend ~our_version =
    Backend.write_bin_prot backend Header.V1.bin_writer_t our_version;
    read_bin_prot ~backend ~name:"Version header" Header.V1.bin_reader_t
    >>=? fun other_versions ->
    Protocol_version_header.negotiate
      ~allow_legacy_peer:true
      ~us:our_version
      ~peer:other_versions
    |> Or_error.map ~f:(fun version ->
      Debug.log_s (fun () ->
        [%message "Negotiated Kerberos version" ~v:(version : int)]);
      `Versioned version)
    |> return
  ;;

  module Server = struct
    let serve_exn
          ?(on_connection = fun _ _ -> `Accept)
          ~accepted_conn_types
          ~principal
          ~peer
          endpoint
          backend
      =
      negotiate backend ~our_version:(Header.V1.value ())
      |> handshake_error
      >>=? function
      | `Versioned 1 ->
        V1.Server.setup
          ~accepted_conn_types
          ~on_connection
          ~principal
          ~peer
          endpoint
          backend
      | `Versioned 2 ->
        V2.Server.setup
          ~accepted_conn_types
          ~on_connection
          ~principal
          ~peer
          endpoint
          backend
      | `Versioned 3 ->
        V3.Server.setup
          ~accepted_conn_types
          ~on_connection
          ~principal
          ~wants_forwarded_creds:false
          ~peer
          endpoint
          backend
      | `Versioned 4 ->
        V4.Server.setup
          ~accepted_conn_types
          ~on_connection
          ~principal
          ~peer
          endpoint
          backend
      | `Versioned version ->
        let e =
          Error.create_s
            [%message
              "Negotiated protocol version that I don't understand (THIS IS A BUG)"
                (version : int)
                ~i_understand:(Header.V1.versions : int list)]
        in
        return (Error (`Handshake_error e))
    ;;

    let serve ?on_connection ~accepted_conn_types ~principal ~peer endpoint backend =
      Deferred.Or_error.try_with
        ~run:
          `Schedule
        ~rest:`Log
        (fun () ->
           serve_exn ?on_connection ~accepted_conn_types ~principal ~peer endpoint backend)
      >>| function
      | Error e -> Error (`Handshake_error e)
      | Ok (_ as result) -> result
    ;;
  end

  module Client = struct
    let negotiate ?override_supported_versions backend =
      let our_version = Header.V1.value ?override_supported_versions () in
      negotiate backend ~our_version
    ;;

    let negotiate_and_setup
          ?override_supported_versions
          ~on_connection
          ~client_cred_cache
          ~accepted_conn_types
          ~peer
          backend
      =
      let cred_cache = Client_cred_cache.cred_cache client_cred_cache in
      negotiate ?override_supported_versions backend
      >>=? function
      | `Versioned 1 ->
        V1.Client.setup ~cred_cache ~accepted_conn_types ~on_connection ~peer backend
        >>|? fun conn -> `Ok conn
      | `Versioned 2 ->
        V2.Client.setup ~cred_cache ~accepted_conn_types ~on_connection ~peer backend
        >>|? fun conn -> `Ok conn
      | `Versioned 3 ->
        V3.Client.setup
          ~cred_cache
          ~accepted_conn_types
          ~on_connection
          ~forward_credentials_if_requested:false
          ~peer
          backend
        >>|? fun conn -> `Ok conn
      | `Versioned 4 ->
        V4.Client.setup
          ~client_cred_cache
          ~accepted_conn_types
          ~on_connection
          ~peer
          backend
        >>|? fun conn -> `Ok conn
      | `Versioned version ->
        Deferred.Or_error.error_s
          [%message
            "Negotiated protocol version that I don't understand (THIS IS A BUG)"
              (version : int)
              ~i_understand:(Header.V1.versions : int list)]
    ;;
  end
end

include Make (Protocol_backend_async)

module Connection = struct
  include Connection

  let reader t = Protocol_backend_async.reader t.backend
  let writer t = Protocol_backend_async.writer t.backend

  let create_for_test_mode ~reader ~writer =
    create_for_test_mode ~backend:(Protocol_backend_async.create ~reader ~writer |> ok_exn)
  ;;
end

module Server = struct
  include Server

  let serve ?on_connection ~accepted_conn_types ~principal ~peer mode reader writer =
    match Protocol_backend_async.create ~reader ~writer with
    | Error err -> return (Error (`Krb_error err))
    | Ok backend ->
      serve ?on_connection ~accepted_conn_types ~principal ~peer mode backend
  ;;
end

module Client = struct
  include Client

  (* This has to be this way because of the way we handle TCP
     reader/writers. If we close the reader first, the writer ends up in an invalid
     state. If it still has data to flush, the next attempted write will raise. By
     making sure [Writer.close] finished, we know the [Writer.t] is flushed and it is
     safe for us to close the reader. *)
  let close_connection_via_reader_and_writer reader writer =
    Writer.close writer ~force_close:(Clock.after (sec 30.))
    >>= fun () -> Reader.close reader
  ;;

  let connect_exn
        ?override_supported_versions
        ?buffer_age_limit
        ?interrupt
        ?reader_buffer_size
        ?writer_buffer_size
        ?(timeout =
          Time_ns.Span.to_span_float_round_nearest
            Async_rpc_kernel.Async_rpc_kernel_private.default_handshake_timeout)
        ?(on_connection = fun _ _ -> `Accept)
        ~client_cred_cache
        ~accepted_conn_types
        where_to_connect
    =
    let finish_handshake_by = Time.add (Time.now ()) timeout in
    Tcp.connect
      ?buffer_age_limit
      ?interrupt
      ?reader_buffer_size
      ?writer_buffer_size
      ~timeout
      where_to_connect
    >>= fun (socket, reader, writer) ->
    return (Protocol_backend_async.create ~reader ~writer)
    >>=? fun backend ->
    let timeout = Time.diff finish_handshake_by (Time.now ()) in
    let peer = Socket.getpeername socket in
    let result =
      Deferred.Or_error.try_with_join
        ~run:
          `Schedule
        ~rest:`Log
        (fun () ->
           negotiate_and_setup
             ?override_supported_versions
             ~on_connection
             ~client_cred_cache
             ~accepted_conn_types
             ~peer
             backend)
    in
    let return_error err =
      let%bind () = close_connection_via_reader_and_writer reader writer in
      Deferred.Or_error.fail
        (Error.tag err ~tag:"The server logs might have more information.")
    in
    match%bind Clock.with_timeout timeout result with
    | `Result (Ok (`Ok res)) -> Deferred.Or_error.return res
    | `Result (Error error) -> return_error error
    | `Timeout ->
      return_error
        (Error.create_s
           [%message "Timed out doing Krb.Rpc handshake" (timeout : Time.Span.t)])
  ;;

  let connect
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
    =
    Deferred.Or_error.try_with_join
      ~run:
        `Schedule
      ~rest:`Log
      (fun () ->
         connect_exn
           ?override_supported_versions
           ?buffer_age_limit
           ?interrupt
           ?reader_buffer_size
           ?writer_buffer_size
           ?timeout
           ?on_connection
           ~client_cred_cache
           ~accepted_conn_types
           where_to_connect)
  ;;
end

module For_test = struct
  module Client = struct
    module V4_header = V4.Header.Client
  end

  module Server = struct
    module V4_header = V4.Header.Server
  end
end
