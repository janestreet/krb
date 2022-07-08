open Core
open Async
open! Import

module Kind : sig
  (** Represents the kind of error that can arise while establishing a kerberized
      connection.

      [Incompatible_client]: The client and server are not compatible
      - The client is speaking a different known protocol. This can happen if the client
        is a standard rpc client and the server isn't using [serve_with_anon]. It can also
        happen if the client is using a different [Mode.t] (e.g. the server is using
        [Kerberized] and the client is using [Test_with_principal])
      - The client and server don't agree on whether there should be authentication,
        integrity-checking and/or encryption (See conn_type.mli)
      - The client and server don't have any overlapping internal protocol versions. We
        maintain backwards compatibility so this should only occur in cross-realm
        environments (which require V5 and above) or when using [Internal] functions that
        take [?override_supported_versions]

      [Unexpected_or_no_client_bytes]: Issues transmitting or reading data
      - Client unexpectedly closes the connection.
      - Client sends unexpected data that doesn't parse

      [Unexpected_exception]: Other unexpected server-side issues.
  *)

  type t =
    | Incompatible_client
    | Unexpected_or_no_client_bytes
    | Unexpected_exception
  [@@deriving sexp_of]
end

type t = Kind.t * Error.t [@@deriving sexp_of]

val of_error : kind:Kind.t -> Error.t -> t

val of_result
  :  kind:Kind.t
  -> ('a, Error.t) Deferred.Result.t
  -> ('a, t) Deferred.Result.t

val ignore_handshake_error_kind
  :  [ `Call of Socket.Address.Inet.t -> exn -> unit | `Ignore | `Raise ]
  -> [ `Call of Kind.t -> Socket.Address.Inet.t -> exn -> unit | `Ignore | `Raise ]
