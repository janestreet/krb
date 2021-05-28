open! Core
open! Async
open! Import


type 'principal authorize = Socket.Address.Inet.t -> 'principal -> [ `Accept | `Reject ]
type t = Principal.Name.t authorize

let bool_to_auth = function
  | true -> `Accept
  | false -> `Reject
;;

module Krb = struct
  let create f = f
  let accept_all _ _ = `Accept

  let accept_single allowed _ principal =
    bool_to_auth (Principal.Name.equal allowed principal)
  ;;

  let accept_multiple allowed _ principal =
    bool_to_auth (Principal.Name.Set.mem allowed principal)
  ;;
end

module Anon = struct
  type t = Principal.Name.t option authorize

  let of_krb ?(on_anon = `Accept) auth addr maybe_principal =
    match maybe_principal with
    | None -> on_anon
    | Some principal -> auth addr principal
  ;;

  let create f = f
  let accept_all = of_krb Krb.accept_all
  let accept_single accepted = of_krb (Krb.accept_single accepted)
  let accept_multiple accepted = of_krb (Krb.accept_multiple accepted)
end

include Krb

let krb_of_anon auth_anon addr principal = auth_anon addr (Some principal)
let anon_of_krb = Anon.of_krb

module For_internal_use = struct
  let authorize auth addr principal = auth addr principal

  module Anon = struct
    let authorize auth addr maybe_principal = auth addr maybe_principal
  end
end
