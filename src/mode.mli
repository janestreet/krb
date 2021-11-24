open! Core

(** A [Mode.t] specifies whether a client or server should use Kerberos for authentication
    or use a test mode where clients/servers can pretend to be any principal. All
    production clients and servers should use [Kerberized] mode.

    When you use the default kerberized mode on both client and server, you will end up
    with encrypted connections. Secure by default! Note that full encryption has a
    performance cost.

    Note that clients can only talk to servers that are running with the same mode
    constructor: a client using [Kerberized] can only talk to a server using [Kerberized].
    Same goes for [Test_with_principal]
*)
type 'a mode =
  | Kerberized of 'a (** The connection will be kerberized. *)
  | Test_with_principal of Principal.Name.t
  (** In test mode, clients/servers can pretend to be any principal. Please note that this
      mode provides NO Kerberos protection. The connection will be plain TCP. *)
[@@deriving compare, hash, sexp_of]

module Client : sig
  type t = Conn_type_preference.t mode [@@deriving compare, hash, sexp_of]

  val kerberized
    :  ?conn_type_preference:Conn_type_preference.t (** default: [accept_all] *)
    -> unit
    -> t

  val test_with_principal
    :  ?test_principal:Principal.Name.t (** default: [User (Unix.getlogin ())] *)
    -> unit
    -> t
end

module Server : sig
  type t = (Server_key_source.t * Conn_type_preference.t) mode
  [@@deriving compare, hash, sexp_of]

  (** Construct a [Kerberized] mode with [Server_key_source.default ()]

      This function will not raise an exception. See [Server_key_source.default]. *)
  val kerberized
    :  ?conn_type_preference:Conn_type_preference.t (** default: [accept_all] *)
    -> key_source:Server_key_source.t
    -> t

  val test_with_principal
    :  ?test_principal:Principal.Name.t (** default: [User (Unix.getlogin ())] *)
    -> unit
    -> t
end

(** The [*_with_auth_conn_type] modes are used for RPC transports that don't support
    transforming data, and thus only support the [Auth] connection type. *)

module Client_with_auth_conn_type : sig
  type t = unit mode [@@deriving compare, hash, sexp_of]

  val kerberized : unit -> t

  val test_with_principal
    :  ?test_principal:Principal.Name.t (** default: [User (Unix.getlogin ())] *)
    -> unit
    -> t

  val full_mode : t -> Client.t
end

module Server_with_auth_conn_type : sig
  type t = Server_key_source.t mode [@@deriving compare, hash, sexp_of]

  val kerberized : key_source:Server_key_source.t -> t

  val test_with_principal
    :  ?test_principal:Principal.Name.t (** default: [User (Unix.getlogin ())] *)
    -> unit
    -> t

  val full_mode : t -> Server.t
end

module Stable : sig
  module V4 : sig
    type nonrec 'a mode = 'a mode [@@deriving bin_io, compare, sexp]

    module Client : Stable_without_comparator with type t = Client.t
    module Server : Stable_without_comparator with type t = Server.t

    module Client_with_auth_conn_type :
      Stable_without_comparator with type t = Client_with_auth_conn_type.t

    module Server_with_auth_conn_type :
      Stable_without_comparator with type t = Server_with_auth_conn_type.t
  end
end
