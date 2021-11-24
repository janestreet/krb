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
      [@@deriving bin_io, compare, sexp]
    end

    module Client_with_auth_conn_type = struct
      type t = unit mode [@@deriving bin_io, compare, sexp]
    end

    module Server_with_auth_conn_type = struct
      type t = Server_key_source.V2.t mode [@@deriving bin_io, compare, sexp]
    end
  end
end

open! Core

type 'a mode = 'a Stable.V4.mode =
  | Kerberized of 'a
  | Test_with_principal of Principal.Name.t
[@@deriving compare, hash, sexp_of]

let default_test_principal = lazy (Principal.Name.User (Core_unix.getlogin ()))

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

  let[@warning "-16"] kerberized
                        ?(conn_type_preference = Conn_type_preference.accept_all)
                        ~key_source
    =
    Kerberized (key_source, conn_type_preference)
  ;;

  let test_with_principal = test_with_principal
end

module Client_with_auth_conn_type = struct
  type t = unit mode [@@deriving compare, hash, sexp_of]

  let kerberized () = Kerberized ()
  let test_with_principal = test_with_principal

  let full_mode t =
    match (t : t) with
    | Test_with_principal _ as t -> t
    | Kerberized () -> Kerberized (Conn_type_preference.accept_only Conn_type.Auth)
  ;;
end

module Server_with_auth_conn_type = struct
  type t = Server_key_source.t mode [@@deriving compare, hash, sexp_of]

  let kerberized ~key_source = Kerberized key_source
  let test_with_principal = test_with_principal

  let full_mode t =
    match (t : t) with
    | Test_with_principal _ as t -> t
    | Kerberized s -> Kerberized (s, Conn_type_preference.accept_only Conn_type.Auth)
  ;;
end
