module Stable = struct
  open! Core.Core_stable

  module V1 = struct
    module User = struct
      type t =
        { username : string
        ; realm : Realm.t
        }
      [@@deriving bin_io, compare, hash, sexp]
    end

    module Service = struct
      type t =
        { service : string
        ; hostname : string
        ; realm : Realm.t
        }
      [@@deriving bin_io, compare, hash, sexp]
    end

    module T = struct
      type t =
        | User of User.t
        | Service of Service.t
      [@@deriving bin_io, compare, hash, sexp]

      include (val Comparator.V1.make ~compare ~sexp_of_t)
    end

    include T
    include Comparable.V1.Make (T)
  end
end

open! Core
open! Async
open! Import

module User = struct
  type t = Stable.V1.User.t =
    { username : string
    ; realm : Realm.t
    }
  [@@deriving compare, fields ~getters, hash, sexp_of]

  let to_string { username; realm } = sprintf "%s@%s" username realm

  let with_default_realm username =
    let open Deferred.Or_error.Let_syntax in
    let%bind realm = Realm.default () in
    return { username; realm }
  ;;

  let%expect_test "to_string" =
    let () =
      { username = "user"; realm = "TEST.REALM.COM" } |> to_string |> print_endline
    in
    [%expect {| user@TEST.REALM.COM |}];
    Deferred.unit
  ;;
end

module Service = struct
  type t = Stable.V1.Service.t =
    { service : string
    ; hostname : string
    ; realm : Realm.t
    }
  [@@deriving compare, fields ~getters, hash, sexp_of]

  let to_string { service; hostname; realm } = sprintf "%s/%s@%s" service hostname realm

  let with_default_realm ~service ~hostname =
    let open Deferred.Or_error.Let_syntax in
    let%bind realm = Realm.default () in
    return { service; hostname; realm }
  ;;

  let%expect_test "to_string" =
    { service = "ftp"; hostname = "bluebird.domain.com"; realm = "TEST.REALM.COM" }
    |> to_string
    |> print_endline;
    [%expect {|
      ftp/bluebird.domain.com@TEST.REALM.COM |}];
    Deferred.unit
  ;;
end

module T = struct
  type t = Stable.V1.t =
    | User of User.t
    | Service of Service.t
  [@@deriving compare, hash, sexp_of]

  type comparator_witness = Stable.V1.comparator_witness

  let comparator = Stable.V1.comparator
end

include T
include Comparable.Make_plain_using_comparator (T)
include Hashable.Make_plain (T)

let realm = function
  | User user -> User.realm user
  | Service service -> Service.realm service
;;

let to_string = function
  | User user -> User.to_string user
  | Service service -> Service.to_string service
;;

let of_string x =
  let open Or_error.Let_syntax in
  match Principal_parser.parse x with
  | { primary; instance = None; realm = Some realm } ->
    return (User { username = primary; realm })
  | { primary; instance = Some instance; realm = Some realm } ->
    return (Service { service = primary; hostname = instance; realm })
  | { realm = None; _ } -> Or_error.error_s [%message "Realm must be supplied" x]
;;

let of_string_exn s = ok_exn (of_string s)
