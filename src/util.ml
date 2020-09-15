open! Core
open! Async
open! Import

module Acting_as = struct
  type _ t =
    | Server : Client_principal.t t
    | Client : Server_principal.t t
  [@@deriving sexp_of]
end

let do_on_connection
      (type peer)
      ~(f : Socket.Address.Inet.t -> peer -> [ `Accept | `Reject ])
      ~(acting_as : peer Acting_as.t)
      ~peer_address
      principal
  =
  let error_on_reject ~me ~peer result =
    match result with
    | `Accept -> Ok ()
    | `Reject ->
      Or_error.error_s
        [%message
          (sprintf "%s rejected %s principal" me peer) (principal : Principal.Name.t)]
  in
  Or_error.try_with_join (fun () ->
    let open Acting_as in
    match acting_as with
    | Server ->
      error_on_reject
        ~me:"server"
        ~peer:"client"
        (f peer_address { Client_principal.client_principal = principal })
    | Client ->
      error_on_reject
        ~me:"client"
        ~peer:"server"
        (f peer_address { Server_principal.server_principal = principal }))
;;
