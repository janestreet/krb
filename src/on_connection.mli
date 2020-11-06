open! Core
open! Async

module Acting_as : sig
  type _ t =
    | Server : Client_principal.t t
    | Client : Server_principal.t t
  [@@deriving sexp_of]
end

val run
  :  f:(Socket.Address.Inet.t -> 'a -> [ `Accept | `Reject ])
  -> acting_as:'a Acting_as.t
  -> peer_address:Socket.Address.Inet.t
  -> Principal.Name.t
  -> unit Or_error.t
