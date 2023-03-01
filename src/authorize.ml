open! Core
open! Async
open! Import


type 'principal authorize =
  Socket.Address.Inet.t -> 'principal -> [ `Accept | `Reject ] Deferred.t

let bool_to_auth = function
  | true -> `Accept
  | false -> `Reject
;;

module Krb = struct
  type t =
    | Single_realm_accept_all
    | Single_realm of Principal.Name.t authorize
    | Cross_realm of Cross_realm_principal_name.t authorize
  [@@deriving variants]

  let create_async f = Single_realm f
  let create f = create_async (fun addr principal -> f addr principal |> Deferred.return)
  let accept_all = Single_realm_accept_all

  let accept_single allowed =
    create (fun _ principal -> bool_to_auth (Principal.Name.equal allowed principal))
  ;;

  let accept_multiple allowed =
    create (fun _ principal -> bool_to_auth (Set.mem allowed principal))
  ;;

  module Cross_realm = struct
    let create f = Cross_realm (fun addr principal -> f addr principal |> Deferred.return)

    let accept_single allowed =
      create (fun _ principal ->
        bool_to_auth (Cross_realm_principal_name.equal allowed principal))
    ;;

    let accept_multiple allowed =
      create (fun _ principal -> bool_to_auth (Set.mem allowed principal))
    ;;
  end
end

module Anon = struct
  type t = Principal.Name.t option authorize

  let of_krb ?(on_anon = `Accept) f addr maybe_principal =
    match maybe_principal with
    | None -> return on_anon
    | Some principal -> f addr principal |> return
  ;;

  let create f addr principal_opt = f addr principal_opt |> Deferred.return
  let accept_all = of_krb (fun _ _ -> `Accept)

  let accept_single allowed =
    of_krb (fun _ principal -> bool_to_auth (Principal.Name.equal allowed principal))
  ;;

  let accept_multiple allowed =
    of_krb (fun _ principal -> bool_to_auth (Set.mem allowed principal))
  ;;
end

include Krb

let krb_of_anon auth_anon =
  create_async (fun addr principal -> auth_anon addr (Some principal))
;;

let authorization_method = function
  | Single_realm_accept_all -> `Accept_all
  | Single_realm _ | Cross_realm _ -> `Custom
;;

module For_internal_use = struct
  let authorize auth addr principal =
    match auth with
    | Single_realm_accept_all -> return `Accept
    | Single_realm single_auth ->
      single_auth addr (Principal.Name.of_cross_realm principal)
    | Cross_realm cr_auth -> cr_auth addr principal
  ;;

  let allows_cross_realm = function
    | Single_realm_accept_all | Single_realm _ -> false
    | Cross_realm _ -> true
  ;;

  module Anon = struct
    let authorize auth addr maybe_principal = auth addr maybe_principal
  end
end
