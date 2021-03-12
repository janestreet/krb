module Stable = struct
  open! Core.Core_stable

  module Name = struct
    module V1 = struct
      module T2 = struct
        module T1 = struct
          type t =
            | User of string
            | Service of
                { service : string
                ; hostname : string
                }
          [@@deriving bin_io, compare, hash, sexp]
        end

        module C = Comparator.V1.Make (T1)
        include T1
        include C
      end

      include T2
      include Comparable.V1.Make (T2)
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

    let hostname_suffix =
      Option.value_map Config.domain_name ~f:(fun x -> "." ^ x) ~default:""
    ;;

    let to_principal = function
      | User s -> Internal.Principal.of_string s
      | Service { service; hostname } ->
        Internal.Principal.of_string (sprintf "%s/%s%s" service hostname hostname_suffix)
    ;;

    let to_string = function
      | User u -> u
      | Service { service; hostname } -> sprintf "%s/%s" service hostname
    ;;

    let of_string x =
      let without_realm =
        Option.value ~default:x (String.chop_suffix x ~suffix:("@" ^ Config.realm))
      in
      match String.rsplit2 ~on:'/' without_realm with
      | None -> User without_realm
      | Some (service, hostname) ->
        let hostname =
          Option.value
            ~default:hostname
            (String.chop_suffix hostname ~suffix:hostname_suffix)
        in
        Service { service; hostname }
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
      Service { service; hostname = Core.Unix.gethostname () }
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

let%test_unit "roundtrip [Name.t]" =
  let test name =
    Thread_safe.block_on_async_exn (fun () ->
      Name.to_principal name
      >>|? fun principal ->
      [%test_result: Name.t] (Name.of_principal principal) ~expect:name)
    |> ok_exn
  in
  test (User "test_user");
  test (Service { service = "test"; hostname = "host" })
;;
