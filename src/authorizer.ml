open! Core

module Acting_as = struct
  type t =
    | Server
    | Client
  [@@deriving sexp_of]
end

let run ~(authorize : Authorize.t) ~(acting_as : Acting_as.t) ~peer_address principal =
  let error_on_reject ~me ~peer result =
    match result with
    | `Accept -> Ok ()
    | `Reject ->
      Or_error.error_s
        [%message
          (sprintf "%s rejected %s principal or address" me peer)
            (principal : Principal.Name.t)
            ~address:(peer_address : Async.Socket.Address.Inet.t)]
  in
  Or_error.try_with_join (fun () ->
    match acting_as with
    | Server ->
      error_on_reject
        ~me:"server"
        ~peer:"client"
        (Authorize.For_internal_use.authorize authorize peer_address principal)
    | Client ->
      error_on_reject
        ~me:"client"
        ~peer:"server"
        (Authorize.For_internal_use.authorize authorize peer_address principal))
;;
