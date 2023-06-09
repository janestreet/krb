module Stable = struct
  open! Core.Core_stable

  module Name = struct
    module V1 = struct
      module T = struct
        type t =
          | User of string
          | Service of
              { service : string
              ; hostname : string
              }
        [@@deriving bin_io, compare, hash, sexp, stable_witness]

        let%expect_test _ =
          print_endline [%bin_digest: t];
          [%expect {| b49cc489842e6ad3217157385a6f94d7 |}]
        ;;

        include (val Comparator.V1.make ~compare ~sexp_of_t)
      end

      include T
      include Comparable.V1.Make (T)
    end
  end
end

open! Core
open! Async
open Import

module Name = struct
  module T = struct
    type t = Stable.Name.V1.t =
      | User of string
      | Service of
          { service : string
          ; hostname : string
          }
    [@@deriving compare, hash, sexp_of]

    type comparator_witness = Stable.Name.V1.comparator_witness

    let comparator = Stable.Name.V1.comparator

    let append_default_domain hostname =
      let hostname_suffix =
        Option.value_map Config.default_domain ~f:(fun x -> "." ^ x) ~default:""
      in
      (* "localhost" is not a hostname that will show up in an SPN, but we use it in some
         tests. *)
      if Config.am_sandboxed && String.equal hostname "localhost"
      then "localhost"
      else hostname ^ hostname_suffix
    ;;

    let to_principal = function
      | User s -> Internal.Principal.of_string s
      | Service { service; hostname } ->
        let hostname = append_default_domain hostname in
        Internal.Principal.of_string (sprintf "%s/%s" service hostname)
    ;;

    let to_string = function
      | User u -> u
      | Service { service; hostname } -> sprintf "%s/%s" service hostname
    ;;

    let of_string x =
      match Principal_parser.parse x with
      | { primary; instance = None; _ } -> User primary
      | { primary; instance = Some instance; _ } ->
        let hostname = Principal_parser.chop_default_domain instance in
        Service { service = primary; hostname }
    ;;

    let of_principal principal = of_string (Internal.Principal.to_string principal)
    let arg = Command.Arg_type.create of_string

    let to_username = function
      | User u -> Some (Username.of_string u)
      | Service _ -> None
    ;;

    let to_username_exn = function
      | User u -> Username.of_string u
      | Service { service; hostname } ->
        raise_s
          [%sexp
            "Could not convert service principal into username"
          , { service : string; hostname : string }]
    ;;

    let service_on_this_host ~service =
      Service { service; hostname = Core_unix.gethostname () }
    ;;

    let of_cross_realm = function
      | Cross_realm_principal_name.User { username; _ } -> User username
      | Service { service; hostname; _ } ->
        let hostname = Principal_parser.chop_default_domain hostname in
        Service { service; hostname }
    ;;

    let with_realm ~realm principal =
      match principal with
      | User user -> Cross_realm_principal_name.User { username = user; realm }
      | Service { service; hostname } ->
        let hostname = append_default_domain hostname in
        Service { service; hostname; realm }
    ;;

    let with_default_realm principal =
      let%map.Deferred.Or_error realm = Realm.default () in
      with_realm ~realm principal
    ;;
  end

  include T
  include Hashable.Make_plain (T)
  include Comparable.Make_plain_using_comparator (T)
end

include Internal.Principal

let name = Name.of_principal
let create = Name.to_principal
let check_password = Internal.Credentials.check_password

let service_with_canonicalized_hostname ~service ~hostname =
  of_hostname_and_service ~hostname ~service ~canonicalize_hostname:true
;;

module Cross_realm = struct
  let create name =
    Internal.Principal.of_string (Cross_realm_principal_name.to_string name)
  ;;

  let name principal =
    (* This [_exn] is safe because the underlying kerberos library uses the default realm
       if none is supplied (see [krb5_parse_name] docs *)
    Cross_realm_principal_name.of_string_exn (Internal.Principal.to_string principal)
  ;;
end

let kvno ?cred_cache server =
  let open Deferred.Or_error.Let_syntax in
  let%bind cred_cache =
    match cred_cache with
    | None -> Internal.Cred_cache.default ()
    | Some cred_cache -> return cred_cache
  in
  let%bind me = Internal.Cred_cache.principal cred_cache in
  let%bind request = Internal.Credentials.create ~client:me ~server () in
  let flags = [ Internal.Krb_flags.Get_credentials.KRB5_GC_NO_STORE ] in
  let%bind credential = Internal.Cred_cache.get_credentials ~flags ~request cred_cache in
  let%map ticket = Internal.Credentials.ticket credential in
  Internal.Ticket.kvno ticket
;;
