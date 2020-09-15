module Stable = struct
  open! Core.Core_stable
  module Conn_type_preference = Conn_type_preference.Stable
  module Server_key_source = Server_key_source.Stable
  module Principal = Principal.Stable

  module V4 = struct
    type 'a mode =
      | Kerberized of 'a
      | Test_with_principal of Principal.Name.V1.t
    [@@deriving bin_io, compare, sexp]

    module Client = struct
      type t = Conn_type_preference.V1.t mode [@@deriving bin_io, compare, sexp]
    end

    module Server = struct
      type t = (Server_key_source.V2.t * Conn_type_preference.V1.t) mode
      [@@deriving compare, sexp]
    end
  end
end

open! Core

type 'a mode = 'a Stable.V4.mode =
  | Kerberized of 'a
  | Test_with_principal of Principal.Name.t
[@@deriving compare, hash, sexp_of]

let default_test_principal = lazy (Principal.Name.User (Core.Unix.getlogin ()))

let test_with_principal ?(test_principal = force default_test_principal) () =
  Test_with_principal test_principal
;;

module Client = struct
  type t = Conn_type_preference.t mode [@@deriving compare, hash, sexp_of]

  let kerberized ?(conn_type_preference = Conn_type_preference.accept_all) () =
    Kerberized conn_type_preference
  ;;

  let test_with_principal = test_with_principal
end

module Server = struct
  type t = (Server_key_source.t * Conn_type_preference.t) mode
  [@@deriving compare, hash, sexp_of]

  let kerberized ?(conn_type_preference = Conn_type_preference.accept_all) ~key_source =
    Kerberized (key_source, conn_type_preference)
  ;;

  let test_with_principal = test_with_principal
end
