open! Core
open! Async
open! Import


type 'principal authorize = Socket.Address.Inet.t -> 'principal -> [ `Accept | `Reject ]

let bool_to_auth = function
  | true -> `Accept
  | false -> `Reject
;;

module Krb = struct
  type t =
    | Single_realm of Principal.Name.t authorize
    | Cross_realm of Cross_realm_principal_name.t authorize
  [@@deriving variants]

  let create f = Single_realm f
  let accept_all = Single_realm (fun _ _ -> `Accept)

  let accept_single allowed =
    Single_realm
      (fun _ principal -> bool_to_auth (Principal.Name.equal allowed principal))
  ;;

  let accept_multiple allowed =
    Single_realm
      (fun _ principal -> bool_to_auth (Principal.Name.Set.mem allowed principal))
  ;;

  module Cross_realm = struct
    let create f = Cross_realm f

    let accept_single allowed =
      Cross_realm
        (fun _ principal ->
           bool_to_auth (Cross_realm_principal_name.equal allowed principal))
    ;;

    let accept_multiple allowed =
      Cross_realm
        (fun _ principal ->
           bool_to_auth (Cross_realm_principal_name.Set.mem allowed principal))
    ;;
  end
end

module Anon = struct
  type t = Principal.Name.t option authorize

  let of_krb ?(on_anon = `Accept) f addr maybe_principal =
    match maybe_principal with
    | None -> on_anon
    | Some principal -> f addr principal
  ;;

  let create f = f
  let accept_all = of_krb (fun _ _ -> `Accept)

  let accept_single allowed =
    of_krb (fun _ principal -> bool_to_auth (Principal.Name.equal allowed principal))
  ;;

  let accept_multiple allowed =
    of_krb (fun _ principal -> bool_to_auth (Principal.Name.Set.mem allowed principal))
  ;;
end

include Krb

let krb_of_anon auth_anon = create (fun addr principal -> auth_anon addr (Some principal))

module For_internal_use = struct
  let authorize auth addr principal =
    match auth with
    | Single_realm single_auth ->
      single_auth addr (Principal.Name.of_cross_realm principal)
    | Cross_realm cr_auth -> cr_auth addr principal
  ;;

  let allows_cross_realm = function
    | Single_realm _ -> false
    | Cross_realm _ -> true
  ;;

  module Anon = struct
    let authorize auth addr maybe_principal = auth addr maybe_principal
  end
end
