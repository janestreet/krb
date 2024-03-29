module Stable = struct
  open! Core.Core_stable
  module Conn_type = Conn_type.Stable
  module Conn_type_preference = Conn_type_preference.Stable

  module Header = struct
    module V1 = struct
      type t = Protocol_version_header.t [@@deriving bin_io, sexp]

      let versions = [ 1; 2; 3; 4; 5 ]
    end
  end

  module V1 = struct
    module Mode = struct
      type t =
        | Service
        | User_to_user of string
      [@@deriving bin_io, sexp]
    end

    module Server_header = struct
      type t =
        { accepted_conn_types : Conn_type.V1.t list
        ; principal : string
        ; endpoint : Mode.t
        }
      [@@deriving bin_io]
    end

    module Client_header = struct
      type t =
        { accepted_conn_types : Conn_type.V1.t list
        ; ap_request : Krb_internal_public.Auth_context.Ap_req.t
        }
      [@@deriving bin_io]
    end
  end

  module V2 = struct
    module Mode = struct
      type t = V1.Mode.t =
        | Service
        | User_to_user of string
      [@@deriving bin_io, sexp]
    end

    module Server_header = struct
      type t =
        { accepted_conn_types : Conn_type_preference.V1.t
        ; principal : Principal.Stable.Name.V1.t
        ; endpoint : Mode.t
        }
      [@@deriving bin_io, sexp]
    end

    module Client_header = struct
      type t =
        { accepted_conn_types : Conn_type_preference.V1.t
        ; ap_request : Bigstring.V1.t
        }
      [@@deriving bin_io, sexp]
    end
  end

  module V3 = struct
    module Mode = struct
      type t = V1.Mode.t =
        | Service
        | User_to_user of string
      [@@deriving bin_io, sexp]
    end

    module Server_header = struct
      type t =
        { accepted_conn_types : Conn_type_preference.V1.t
        ; principal : Principal.Stable.Name.V1.t
        ; endpoint : Mode.t
        ; wants_forwarded_creds : bool
        }
      [@@deriving bin_io, sexp]
    end

    module Client_header = struct
      type t =
        { accepted_conn_types : Conn_type_preference.V1.t
        ; ap_request : Bigstring.V1.t
        ; forward_credentials_if_requested : bool
        }
      [@@deriving bin_io, sexp]
    end
  end

  module V4 = struct
    module Mode = struct
      type t = V1.Mode.t =
        | Service
        | User_to_user of string
      [@@deriving bin_io, sexp]
    end

    module Server_header = struct
      type t =
        { accepted_conn_types : Conn_type_preference.V1.t
        ; principal : Principal.Stable.Name.V1.t
        ; endpoint : Mode.t
        }
      [@@deriving bin_io, fields ~getters, sexp]
    end

    module Client_header = struct
      type t =
        { accepted_conn_types : Conn_type_preference.V1.t
        ; ap_request : Bigstring.V1.t
        ; forwarded_creds_ap_request : Bigstring.V1.t
        }
      [@@deriving bin_io, fields ~getters, sexp]
    end
  end

  module V5 = struct
    module Mode = struct
      type t = V1.Mode.t =
        | Service
        | User_to_user of string
      [@@deriving bin_io, sexp]
    end

    module Server_header = struct
      type t =
        { accepted_conn_types : Conn_type_preference.V1.t
        ; principal : Cross_realm_principal_name.Stable.V1.t
        ; endpoint : Mode.t
        }
      [@@deriving bin_io, sexp]
    end

    module Client_header = struct
      type t = V4.Client_header.t =
        { accepted_conn_types : Conn_type_preference.V1.t
        ; ap_request : Bigstring.V1.t
        ; forwarded_creds_ap_request : Bigstring.V1.t
        }
      [@@deriving bin_io, sexp]
    end
  end
end

open Core
open Async
open Import
include Protocol_intf
module Auth_context = Internal.Auth_context
module Credentials = Internal.Credentials
module Flags = Internal.Krb_flags
module Debug = Internal.Debug

let krb_error = Deferred.Result.map_error ~f:(fun e -> `Krb_error e)
let handshake_error' ~kind error = `Handshake_error (Handshake_error.of_error ~kind error)
let handshake_error ~kind r = Deferred.Result.map_error r ~f:(handshake_error' ~kind)
let supported_versions = Stable.Header.V1.versions

module Make (Backend : Protocol_backend_intf.S) = struct
  type protocol_backend = Backend.t

  module Connection = struct
    type protocol_backend = Backend.t

    type t =
      { backend : Backend.t
      ; auth_context : [ `Test_mode | `Prod of Auth_context.t ]
      ; conn_type : Conn_type.t
      ; forwarded_creds_auth_context : Auth_context.t option
      ; cred_cache : Internal.Cred_cache.t option
      ; my_principal : Cross_realm_principal_name.t
      ; peer_principal : Cross_realm_principal_name.t
      ; protocol_version : [ `Test_mode | `Versioned of int ]
      }
    [@@deriving fields ~getters ~iterators:create]

    module Cross_realm = struct
      let my_principal = my_principal
      let peer_principal = peer_principal
    end

    let my_principal t = Cross_realm.my_principal t |> Principal.Name.of_cross_realm
    let peer_principal t = Cross_realm.peer_principal t |> Principal.Name.of_cross_realm
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
        Tgt.Cross_realm.ensure_valid
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
      let%bind client = Principal.Cross_realm.create t.my_principal in
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
              ~required_protocol_version:
                ([ `Versioned 4; `Versioned 5 ] : [ `Versioned of int ] list)
              ~negotiated_protocol_version:
                (t.protocol_version : [ `Test_mode | `Versioned of int ])]
    ;;

    let read_krb_cred t krb_cred =
      let open Deferred.Or_error.Let_syntax in
      let%bind cred_cache =
        Cred_cache.Cross_realm.in_memory_for_principal t.peer_principal
      in
      match t.forwarded_creds_auth_context with
      | None ->
        Deferred.Or_error.error_s
          [%message
            "Unable to read krb_cred for forwarded credentials"
              ~required_protocol_version:
                ([ `Versioned 4; `Versioned 5 ] : [ `Versioned of int ] list)
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
      Error (handshake_error' ~kind:Unexpected_or_no_client_bytes error)
    | `Ok res -> Ok res
  ;;

  let read_bin_prot ~backend ~name bin_reader =
    match%map read_bin_prot' ~backend ~name bin_reader with
    | Error (`Handshake_error (_, e)) -> Error e
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
    |> handshake_error ~kind:Unexpected_or_no_client_bytes
  ;;

  let read_field ~conn_type ~auth_context ~backend ~name bin_reader =
    match%map read_field' ~conn_type ~auth_context ~backend ~name bin_reader with
    | Error (`Krb_error e) | Error (`Handshake_error (_, e)) -> Error e
    | Ok _ as res -> res
  ;;

  let write_field' ~conn_type ~auth_context ~backend bin_writer value =
    let bs = Bin_prot.Utils.bin_dump ~header:true bin_writer value in
    (match (conn_type : Conn_type.t) with
     | Auth -> Deferred.Or_error.return bs
     | Safe -> Auth_context.Safe.encode auth_context (Bigsubstring.create bs)
     | Priv -> Auth_context.Priv.encode auth_context (Bigsubstring.create bs))
    |> krb_error
    >>|? fun x -> Backend.write_bin_prot_exn backend Bigstring.Stable.V1.bin_writer_t x
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
      type t = Stable.V1.Mode.t =
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
        type t = Stable.V1.Server_header.t =
          { accepted_conn_types : Conn_type.V1.t list
          ; principal : string
          ; endpoint : Mode.t
          }
        [@@deriving bin_io, fields ~getters ~iterators:create]

        let write ~backend t = Backend.write_bin_prot_exn backend bin_writer_t t
        let read ~backend = read_bin_prot ~backend ~name:"Server header" bin_reader_t
      end

      module Client = struct
        type t = Stable.V1.Client_header.t =
          { accepted_conn_types : Conn_type.V1.t list
          ; ap_request : Ap_req.t
          }
        [@@deriving bin_io, fields ~getters ~iterators:create]

        let write ~backend t = Backend.write_bin_prot_exn backend bin_writer_t t
        let read' ~backend = read_bin_prot' ~backend ~name:"Client header" bin_reader_t
      end
    end

    let handle_error ~backend tag result =
      Result.iter_error result ~f:(fun _ ->
        let e = Error.createf "This value will never be read" in
        Backend.write_bin_prot_exn
          backend
          (Or_error.Stable.V2.bin_writer_t Unit.bin_writer_t)
          (Or_error.tag ~tag (Error e)));
      result
    ;;

    module Server = struct
      let do_setup ~conn_type_preference ~authorize ~principal ~peer endpoint backend =
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
          Unstable.Conn_type_preference.to_set conn_type_preference
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
        |> handshake_error ~kind:Incompatible_client
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
        let client_principal_name = Principal.Cross_realm.name client in
        let my_principal = Principal.Cross_realm.name principal in
        Authorizer.run
          ~authorize
          ~acting_as:Server
          ~my_principal
          ~peer_address:peer
          ~peer_principal:client_principal_name
        >>= fun authorize_result ->
        write_field'
          ~conn_type
          ~auth_context
          ~backend
          (Or_error.Stable.V2.bin_writer_t Unit.bin_writer_t)
          authorize_result
        >>=? fun () ->
        read_field' ~conn_type ~auth_context ~backend ~name:"Client ack" Unit.bin_reader_t
        >>|? fun () ->
        let conn =
          Connection.create_no_forwarded_creds
            ~conn_type
            ~auth_context:(`Prod auth_context)
            ~backend
            ~my_principal
            ~peer_principal:client_principal_name
            ~protocol_version:(`Versioned 1)
        in
        conn, authorize_result
      ;;

      let setup ~conn_type_preference ~authorize ~principal ~peer endpoint backend =
        do_setup ~conn_type_preference ~authorize ~principal ~peer endpoint backend
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

      let setup ~cred_cache ~conn_type_preference ~authorize ~peer backend =
        Header.Server.read ~backend
        >>=? fun server_header ->
        let accepted_conn_types =
          Unstable.Conn_type_preference.to_set conn_type_preference
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
        Cred_cache.Cross_realm.principal cred_cache
        >>=? fun my_principal ->
        let server_principal_name = Principal.Cross_realm.name server_principal in
        Authorizer.run
          ~authorize
          ~acting_as:Client
          ~my_principal
          ~peer_address:peer
          ~peer_principal:server_principal_name
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
        >>|? fun () ->
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
      type t = Stable.V2.Mode.t =
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
        type t = Stable.V2.Server_header.t =
          { accepted_conn_types : Conn_type_preference.V1.t
          ; principal : Principal.Stable.Name.V1.t
          ; endpoint : Mode.t
          }
        [@@deriving bin_io, fields ~getters ~iterators:create, sexp]

        let write ~backend t = Backend.write_bin_prot_exn backend bin_writer_t t
        let read ~backend = read_bin_prot ~backend ~name:"Server header" bin_reader_t
      end

      module Client = struct
        type t = Stable.V2.Client_header.t =
          { accepted_conn_types : Conn_type_preference.V1.t
          ; ap_request : Bigstring.Stable.V1.t
          }
        [@@deriving bin_io, fields ~getters ~iterators:create, sexp]

        let write ~backend t = Backend.write_bin_prot_exn backend bin_writer_t t
        let read' ~backend = read_bin_prot' ~backend ~name:"Client header" bin_reader_t
      end

      module Ap_rep = struct
        let write ~backend t =
          Backend.write_bin_prot_exn backend Auth_context.Ap_rep.bin_writer_t t
        ;;

        let read ~backend =
          read_bin_prot ~backend ~name:"Ap_rep" Auth_context.Ap_rep.bin_reader_t
        ;;
      end
    end

    module Server = struct
      let do_setup ~conn_type_preference ~authorize ~principal ~peer endpoint backend =
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
            ~accepted_conn_types:conn_type_preference
            ~principal:(Principal.name principal)
            ~endpoint
        in
        Header.Server.write ~backend header;
        Header.Client.read' ~backend
        >>=? fun client_header ->
        Unstable.Conn_type_preference.negotiate
          ~us:conn_type_preference
          ~peer:(Header.Client.accepted_conn_types client_header)
        |> return
        |> handshake_error ~kind:Incompatible_client
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
        let my_principal = Principal.Cross_realm.name principal in
        let client_principal_name = Principal.Cross_realm.name client in
        Authorizer.run
          ~authorize
          ~acting_as:Server
          ~my_principal
          ~peer_address:peer
          ~peer_principal:client_principal_name
        >>= fun authorize_result ->
        (* These acks are probably not necessary at this point, but it is a good sanity
           check that both the client and server can encrypt/decrypt with the correct
           connection type. *)
        write_field'
          ~conn_type
          ~auth_context
          ~backend
          (Or_error.Stable.V2.bin_writer_t Unit.bin_writer_t)
          authorize_result
        >>=? fun () ->
        read_field' ~conn_type ~auth_context ~backend ~name:"Client ack" Unit.bin_reader_t
        >>|? fun () ->
        let conn =
          Connection.create_no_forwarded_creds
            ~conn_type
            ~auth_context:(`Prod auth_context)
            ~backend
            ~my_principal
            ~peer_principal:client_principal_name
            ~protocol_version:(`Versioned 2)
        in
        conn, authorize_result
      ;;

      let setup ~conn_type_preference ~authorize ~principal ~peer endpoint backend =
        do_setup ~conn_type_preference ~authorize ~principal ~peer endpoint backend
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

      let setup ~cred_cache ~conn_type_preference ~authorize ~peer backend =
        Header.Server.read ~backend
        >>=? fun server_header ->
        Unstable.Conn_type_preference.negotiate
          ~us:conn_type_preference
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
            ~accepted_conn_types:conn_type_preference
            ~ap_request
        in
        Header.Client.write ~backend client_header;
        Header.Ap_rep.read ~backend
        >>=? fun ap_rep ->
        Auth_context.Client.read_and_verify_ap_rep auth_context ~ap_rep
        >>=? fun () ->
        Header.Server.principal server_header
        |> Principal.Name.with_default_realm
        >>=? fun server_principal_name ->
        Cred_cache.Cross_realm.principal cred_cache
        >>=? fun my_principal ->
        (* Check the server principal after receiving the [ap_rep]. Otherwise, we can't
           trust the principal if the connection type is [Auth]. *)
        Authorizer.run
          ~authorize
          ~acting_as:Client
          ~my_principal
          ~peer_address:peer
          ~peer_principal:server_principal_name
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
        >>|? fun () ->
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
      type t = Stable.V3.Mode.t =
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
        type t = Stable.V3.Server_header.t =
          { accepted_conn_types : Conn_type_preference.V1.t
          ; principal : Principal.Stable.Name.V1.t
          ; endpoint : Mode.t
          ; wants_forwarded_creds : bool
          }
        [@@deriving bin_io, fields ~getters ~iterators:create, sexp]

        let write ~backend t = Backend.write_bin_prot_exn backend bin_writer_t t
        let read ~backend = read_bin_prot ~backend ~name:"Server header" bin_reader_t
      end

      module Client = struct
        type t = Stable.V3.Client_header.t =
          { accepted_conn_types : Conn_type_preference.V1.t
          ; ap_request : Bigstring.Stable.V1.t
          ; forward_credentials_if_requested : bool
          }
        [@@deriving bin_io, fields ~getters ~iterators:create, sexp]

        let write ~backend t = Backend.write_bin_prot_exn backend bin_writer_t t
        let read' ~backend = read_bin_prot' ~backend ~name:"Client header" bin_reader_t
      end

      module Ap_rep = struct
        let write ~backend t =
          Backend.write_bin_prot_exn backend Auth_context.Ap_rep.bin_writer_t t
        ;;

        let read ~backend =
          read_bin_prot ~backend ~name:"Ap_rep" Auth_context.Ap_rep.bin_reader_t
        ;;
      end
    end

    module Server = struct
      let do_setup
        ~conn_type_preference
        ~authorize
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
            ~accepted_conn_types:conn_type_preference
            ~principal:(Principal.name principal)
            ~endpoint
            ~wants_forwarded_creds
        in
        Header.Server.write ~backend header;
        Header.Client.read' ~backend
        >>=? fun client_header ->
        Unstable.Conn_type_preference.negotiate
          ~us:conn_type_preference
          ~peer:(Header.Client.accepted_conn_types client_header)
        |> return
        |> handshake_error ~kind:Incompatible_client
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
        let client_principal_name = Principal.Cross_realm.name client in
        let my_principal = Principal.Cross_realm.name principal in
        Authorizer.run
          ~authorize
          ~acting_as:Server
          ~peer_address:peer
          ~peer_principal:client_principal_name
          ~my_principal
        >>= fun authorize_result ->
        (* These acks are probably not necessary at this point, but it is a good sanity
           check that both the client and server can encrypt/decrypt with the correct
           connection type. *)
        write_field'
          ~conn_type
          ~auth_context
          ~backend
          (Or_error.Stable.V2.bin_writer_t Unit.bin_writer_t)
          authorize_result
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
              Cred_cache.Cross_realm.in_memory_for_principal client_principal_name
              |> krb_error
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
            ~my_principal
            ~peer_principal:client_principal_name
            ~protocol_version:(`Versioned this_version)
        in
        conn, authorize_result
      ;;

      let setup
        ~conn_type_preference
        ~authorize
        ~principal
        ~wants_forwarded_creds
        ~peer
        endpoint
        backend
        =
        do_setup
          ~conn_type_preference
          ~authorize
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
        ~conn_type_preference
        ~authorize
        ~forward_credentials_if_requested
        ~peer
        backend
        =
        Header.Server.read ~backend
        >>=? fun server_header ->
        Unstable.Conn_type_preference.negotiate
          ~us:conn_type_preference
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
            ~accepted_conn_types:conn_type_preference
            ~ap_request
            ~forward_credentials_if_requested
        in
        Header.Client.write ~backend client_header;
        Header.Ap_rep.read ~backend
        >>=? fun ap_rep ->
        Auth_context.Client.read_and_verify_ap_rep auth_context ~ap_rep
        >>=? fun () ->
        Header.Server.principal server_header
        |> Principal.Name.with_default_realm
        >>=? fun server_principal_name ->
        Cred_cache.Cross_realm.principal cred_cache
        >>=? fun my_principal ->
        (* Check the server principal after receiving the [ap_rep]. Otherwise, we can't
           trust the principal if the connection type is [Auth]. *)
        Authorizer.run
          ~authorize
          ~acting_as:Client
          ~my_principal
          ~peer_address:peer
          ~peer_principal:server_principal_name
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
            Backend.write_bin_prot_exn backend Auth_context.Krb_cred.bin_writer_t krb_cred;
            return ())
          else return ())
        >>|? fun () ->
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
      type t = Stable.V4.Mode.t =
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
        type t = Stable.V4.Server_header.t =
          { accepted_conn_types : Conn_type_preference.V1.t
          ; principal : Principal.Stable.Name.V1.t
          ; endpoint : Mode.t
          }
        [@@deriving bin_io, fields ~getters ~iterators:create, sexp]

        let write ~backend t = Backend.write_bin_prot_exn backend bin_writer_t t
        let read ~backend = read_bin_prot ~backend ~name:"Server header" bin_reader_t
      end

      module Client = struct
        type t = Stable.V4.Client_header.t =
          { accepted_conn_types : Conn_type_preference.V1.t
          ; ap_request : Bigstring.Stable.V1.t
          ; forwarded_creds_ap_request : Bigstring.Stable.V1.t
          }
        [@@deriving bin_io, fields ~getters ~iterators:create, sexp]

        let write ~backend t = Backend.write_bin_prot_exn backend bin_writer_t t
        let read' ~backend = read_bin_prot' ~backend ~name:"Client header" bin_reader_t
      end

      module Ap_rep = struct
        let write ~backend t =
          Backend.write_bin_prot_exn backend Auth_context.Ap_rep.bin_writer_t t
        ;;

        let read ~backend =
          read_bin_prot ~backend ~name:"Ap_rep" Auth_context.Ap_rep.bin_reader_t
        ;;
      end
    end

    module Server = struct
      let do_setup ~conn_type_preference ~authorize ~principal ~peer endpoint backend =
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
            ~accepted_conn_types:conn_type_preference
            ~principal:(Principal.name principal)
            ~endpoint
        in
        Header.Server.write ~backend header;
        Header.Client.read' ~backend
        >>=? fun client_header ->
        Unstable.Conn_type_preference.negotiate
          ~us:conn_type_preference
          ~peer:(Header.Client.accepted_conn_types client_header)
        |> return
        |> handshake_error ~kind:Incompatible_client
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
        let my_principal = Principal.Cross_realm.name principal in
        let client_principal_name = Principal.Cross_realm.name client in
        Authorizer.run
          ~authorize
          ~acting_as:Server
          ~my_principal
          ~peer_address:peer
          ~peer_principal:client_principal_name
        >>= fun authorize_result ->
        (* These acks are probably not necessary at this point, but it is a good sanity
           check that both the client and server can encrypt/decrypt with the correct
           connection type. *)
        write_field'
          ~conn_type
          ~auth_context
          ~backend
          (Or_error.Stable.V2.bin_writer_t Unit.bin_writer_t)
          authorize_result
        >>=? fun () ->
        read_field' ~conn_type ~auth_context ~backend ~name:"Client ack" Unit.bin_reader_t
        >>|? fun () ->
        let conn =
          Connection.create_server
            ~conn_type
            ~auth_context:(`Prod auth_context)
            ~forwarded_creds_auth_context:(Some forwarded_creds_auth_context)
            ~backend
            ~my_principal
            ~peer_principal:client_principal_name
            ~protocol_version:(`Versioned this_version)
        in
        conn, authorize_result
      ;;

      let setup ~conn_type_preference ~authorize ~principal ~peer endpoint backend =
        do_setup ~conn_type_preference ~authorize ~principal ~peer endpoint backend
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
               "Failed to get credentials from default cache (succeeded with memory \
                cache)"
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

      let setup ~client_cred_cache ~conn_type_preference ~authorize ~peer backend =
        Header.Server.read ~backend
        >>=? fun server_header ->
        Unstable.Conn_type_preference.negotiate
          ~us:conn_type_preference
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
            ~accepted_conn_types:conn_type_preference
            ~ap_request
            ~forwarded_creds_ap_request
        in
        Header.Client.write ~backend client_header;
        Header.Ap_rep.read ~backend
        >>=? fun ap_rep ->
        Auth_context.Client.read_and_verify_ap_rep auth_context ~ap_rep
        >>=? fun () ->
        Header.Server.principal server_header
        |> Principal.Name.with_default_realm
        >>=? fun server_principal_name ->
        let cred_cache = Client_cred_cache.cred_cache client_cred_cache in
        Cred_cache.Cross_realm.principal cred_cache
        >>=? fun my_principal ->
        (* Check the server principal after receiving the [ap_rep]. Otherwise, we can't
           trust the principal if the connection type is [Auth]. *)
        Authorizer.run
          ~authorize
          ~acting_as:Client
          ~my_principal
          ~peer_address:peer
          ~peer_principal:server_principal_name
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
        >>|? fun () ->
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

  (* Equivalent to V4 but server header uses a [Cross_realm_principal_name] rather than a
     [Principal.Name.t]. This is needed for cross-realm support *)
  module V5 = struct
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
      type t = Stable.V5.Mode.t =
        | Service
        | User_to_user of string
      [@@deriving bin_io, sexp]

      let is_user_to_user = function
        | Service -> false
        | User_to_user _ -> true
      ;;
    end

    let this_version = 5

    module Header = struct
      module Server = struct
        type t = Stable.V5.Server_header.t =
          { accepted_conn_types : Conn_type_preference.V1.t
          ; principal : Cross_realm_principal_name.Stable.V1.t
          ; endpoint : Mode.t
          }
        [@@deriving bin_io, fields ~getters ~iterators:create, sexp]

        let write ~backend t = Backend.write_bin_prot_exn backend bin_writer_t t
        let read ~backend = read_bin_prot ~backend ~name:"Server header" bin_reader_t
      end

      module Client = struct
        type t = Stable.V5.Client_header.t =
          { accepted_conn_types : Conn_type_preference.V1.t
          ; ap_request : Bigstring.Stable.V1.t
          ; forwarded_creds_ap_request : Bigstring.Stable.V1.t
          }
        [@@deriving bin_io, fields ~getters ~iterators:create, sexp]

        let write ~backend t = Backend.write_bin_prot_exn backend bin_writer_t t
        let read' ~backend = read_bin_prot' ~backend ~name:"Client header" bin_reader_t
      end

      module Ap_rep = struct
        let write ~backend t =
          Backend.write_bin_prot_exn backend Auth_context.Ap_rep.bin_writer_t t
        ;;

        let read ~backend =
          read_bin_prot ~backend ~name:"Ap_rep" Auth_context.Ap_rep.bin_reader_t
        ;;
      end
    end

    module Server = struct
      let do_setup ~conn_type_preference ~authorize ~principal ~peer endpoint backend =
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
            ~accepted_conn_types:conn_type_preference
            ~principal:(Principal.Cross_realm.name principal)
            ~endpoint
        in
        Header.Server.write ~backend header;
        Header.Client.read' ~backend
        >>=? fun client_header ->
        Unstable.Conn_type_preference.negotiate
          ~us:conn_type_preference
          ~peer:(Header.Client.accepted_conn_types client_header)
        |> return
        |> handshake_error ~kind:Incompatible_client
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
        let my_principal = Principal.Cross_realm.name principal in
        let client_principal_name = Principal.Cross_realm.name client in
        Authorizer.run
          ~authorize
          ~acting_as:Server
          ~my_principal
          ~peer_address:peer
          ~peer_principal:client_principal_name
        >>= fun authorize_result ->
        (* These acks are probably not necessary at this point, but it is a good sanity
           check that both the client and server can encrypt/decrypt with the correct
           connection type. *)
        write_field'
          ~conn_type
          ~auth_context
          ~backend
          (Or_error.Stable.V2.bin_writer_t Unit.bin_writer_t)
          authorize_result
        >>=? fun () ->
        read_field' ~conn_type ~auth_context ~backend ~name:"Client ack" Unit.bin_reader_t
        >>|? fun () ->
        let conn =
          Connection.create_server
            ~conn_type
            ~auth_context:(`Prod auth_context)
            ~forwarded_creds_auth_context:(Some forwarded_creds_auth_context)
            ~backend
            ~my_principal
            ~peer_principal:client_principal_name
            ~protocol_version:(`Versioned this_version)
        in
        conn, authorize_result
      ;;

      let setup ~conn_type_preference ~authorize ~principal ~peer endpoint backend =
        do_setup ~conn_type_preference ~authorize ~principal ~peer endpoint backend
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
        Header.Server.principal server_header
        |> Principal.Cross_realm.create
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
               "Failed to get credentials from default cache (succeeded with memory \
                cache)"
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

      let setup ~client_cred_cache ~conn_type_preference ~authorize ~peer backend =
        Header.Server.read ~backend
        >>=? fun server_header ->
        Unstable.Conn_type_preference.negotiate
          ~us:conn_type_preference
          ~peer:(Header.Server.accepted_conn_types server_header)
        |> return
        >>=? fun conn_type ->
        let cred_cache = Client_cred_cache.cred_cache client_cred_cache in
        Cred_cache.Cross_realm.principal cred_cache
        >>=? fun my_principal ->
        let server_principal_name = Header.Server.principal server_header in
        (* Check the server principal before sending the [ap_req]. This prevents a
           hijacked server from getting its hands on an [ap_req] for servers the client
           doesn't trust. *)
        Authorizer.run
          ~authorize
          ~acting_as:Client
          ~my_principal
          ~peer_address:peer
          ~peer_principal:server_principal_name
        >>=? fun () ->
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
            ~accepted_conn_types:conn_type_preference
            ~ap_request
            ~forwarded_creds_ap_request
        in
        Header.Client.write ~backend client_header;
        Header.Ap_rep.read ~backend
        >>=? fun ap_rep ->
        Auth_context.Client.read_and_verify_ap_rep auth_context ~ap_rep
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
        >>|? fun () ->
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

  module Negotiate = struct
    let cross_realm_min_version = V5.this_version

    (*
       Protocol versions before V5 do not pass the realm along with the
       principal. To deal with this issue, we force all parties that
       are not in [Config.pre_v5_assumed_realm] to use V5 and above. As
       a result, all cross-realm communication will be over V5 at a minimum
       and hence pass along the realm on the wire.
    *)

    let should_force_cross_realm_min_version principal =
      let my_realm = Internal.Principal.realm principal in
      not (String.equal my_realm Config.pre_v5_assumed_realm)
    ;;

    let negotiate'
      ?(override_supported_versions = Header.V1.versions)
      ?additional_magic_numbers
      ~backend
      principal
      =
      let force_cross_realm_min_version =
        should_force_cross_realm_min_version principal
      in
      let advertised_versions =
        let supported_versions =
          if force_cross_realm_min_version
          then
            List.filter
              ~f:(fun version -> cross_realm_min_version <= version)
              override_supported_versions
          else override_supported_versions
        in
        Protocol_version_header.create_exn
          ?additional_magic_numbers
          ()
          ~protocol:Krb
          ~supported_versions
      in
      Backend.write_bin_prot_exn backend Header.V1.bin_writer_t advertised_versions;
      read_bin_prot' ~backend ~name:"Version header" Header.V1.bin_reader_t
      >>=? fun other_versions ->
      Protocol_version_header.negotiate
        ~allow_legacy_peer:true
        ~us:advertised_versions
        ~peer:other_versions
      |> Result.map_error ~f:(fun error ->
           if force_cross_realm_min_version
           then (
             (* Check whether negotiation would have succeeded without forcing V5+ *)
             match
               Protocol_version_header.negotiate
                 ~allow_legacy_peer:true
                 ~us:
                   (Protocol_version_header.create_exn
                      ()
                      ~protocol:Krb
                      ~supported_versions:override_supported_versions)
                 ~peer:other_versions
             with
             | Ok _ ->
               Error.create_s
                 [%message
                   "Failed to negotate Kerberos version. The process is not running in \
                    the \"pre-v5 realm\" (Config.pre_v5_assumed_realm), and hence a \
                    minimum version of 5 is forced."
                     (error : Error.t)]
             | Error _ -> error)
           else error)
      |> Or_error.map ~f:(fun version ->
           Debug.log_s (fun () ->
             [%message "Negotiated Kerberos version" ~v:(version : int)]);
           `Versioned version)
      |> return
      |> handshake_error ~kind:Incompatible_client
    ;;

    let negotiate ?override_supported_versions ~backend principal =
      match%map negotiate' ?override_supported_versions ~backend principal with
      | Error (`Handshake_error (_, e)) -> Error e
      | Ok _ as res -> res
    ;;
  end

  module Server = struct
    let handshake_exn
      ?override_supported_versions
      ?additional_magic_numbers
      ~authorize
      ~conn_type_preference
      ~principal
      ~peer
      endpoint
      backend
      =
      Negotiate.negotiate'
        ?override_supported_versions
        ?additional_magic_numbers
        ~backend
        principal
      >>=? function
      | `Versioned 1 ->
        V1.Server.setup ~conn_type_preference ~authorize ~principal ~peer endpoint backend
      | `Versioned 2 ->
        V2.Server.setup ~conn_type_preference ~authorize ~principal ~peer endpoint backend
      | `Versioned 3 ->
        V3.Server.setup
          ~conn_type_preference
          ~authorize
          ~principal
          ~wants_forwarded_creds:false
          ~peer
          endpoint
          backend
      | `Versioned 4 ->
        V4.Server.setup ~conn_type_preference ~authorize ~principal ~peer endpoint backend
      | `Versioned 5 ->
        V5.Server.setup ~conn_type_preference ~authorize ~principal ~peer endpoint backend
      | `Versioned version ->
        let e =
          Error.create_s
            [%message
              "Negotiated protocol version that I don't understand (THIS IS A BUG)"
                (version : int)
                ~i_understand:(Header.V1.versions : int list)]
        in
        return (Error (handshake_error' ~kind:Incompatible_client e))
    ;;

    let handshake
      ?override_supported_versions
      ?additional_magic_numbers
      ~authorize
      ~conn_type_preference
      ~principal
      ~peer
      endpoint
      backend
      =
      Deferred.Or_error.try_with ~run:`Schedule ~here:[%here] (fun () ->
        handshake_exn
          ?override_supported_versions
          ?additional_magic_numbers
          ~authorize
          ~conn_type_preference
          ~principal
          ~peer
          endpoint
          backend)
      >>| function
      | Error e -> Error (handshake_error' ~kind:Unexpected_exception e)
      | Ok (_ as result) -> result
    ;;
  end

  module Client = struct
    let handshake_exn
      ?override_supported_versions
      ~authorize
      ~client_cred_cache
      ~conn_type_preference
      ~peer
      backend
      =
      let cred_cache = Client_cred_cache.cred_cache client_cred_cache in
      Internal.Cred_cache.principal cred_cache
      >>=? fun my_principal ->
      Negotiate.negotiate ?override_supported_versions ~backend my_principal
      >>=? function
      | `Versioned 1 ->
        V1.Client.setup ~cred_cache ~conn_type_preference ~authorize ~peer backend
      | `Versioned 2 ->
        V2.Client.setup ~cred_cache ~conn_type_preference ~authorize ~peer backend
      | `Versioned 3 ->
        V3.Client.setup
          ~cred_cache
          ~conn_type_preference
          ~authorize
          ~forward_credentials_if_requested:false
          ~peer
          backend
      | `Versioned 4 ->
        V4.Client.setup ~client_cred_cache ~conn_type_preference ~authorize ~peer backend
      | `Versioned 5 ->
        V5.Client.setup ~client_cred_cache ~conn_type_preference ~authorize ~peer backend
      | `Versioned version ->
        Deferred.Or_error.error_s
          [%message
            "Negotiated protocol version that I don't understand (THIS IS A BUG)"
              (version : int)
              ~i_understand:(Header.V1.versions : int list)]
    ;;

    let handshake
      ?override_supported_versions
      ~authorize
      ~client_cred_cache
      ~conn_type_preference
      ~peer
      backend
      =
      Monitor.try_with_join_or_error ~rest:`Raise (fun () ->
        handshake_exn
          ?override_supported_versions
          ~authorize
          ~client_cred_cache
          ~conn_type_preference
          ~peer
          backend)
    ;;
  end
end
