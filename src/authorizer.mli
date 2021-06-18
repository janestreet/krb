open! Core
open Async

module Acting_as : sig
  type t =
    | Server
    | Client
  [@@deriving sexp_of]
end

val run
  :  authorize:Authorize.t
  -> acting_as:Acting_as.t
  -> my_principal:Cross_realm_principal_name.t
  -> peer_address:Socket.Address.Inet.t
  -> peer_principal:Cross_realm_principal_name.t
  -> unit Or_error.t
