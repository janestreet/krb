open! Core

module Acting_as = struct
  type t =
    | Server
    | Client
  [@@deriving sexp_of]
end

let validate_cross_realm ~authorize ~my_principal ~peer_principal =
  let allow_cross_realm = Authorize.For_internal_use.allows_cross_realm authorize in
  let same_realm =
    [%compare.equal: Realm.t]
      (Cross_realm_principal_name.realm my_principal)
      (Cross_realm_principal_name.realm peer_principal)
  in
  if (not same_realm) && not allow_cross_realm
  then
    `Reject
      (Some
         (Error.create_s
            [%message
              "Cross realm is disabled." ~by:(my_principal : Cross_realm_principal_name.t)]))
  else `Accept
;;

let run_sided ~(acting_as : Acting_as.t) ~peer_principal ~peer_address f =
  let me, peer =
    match acting_as with
    | Server -> "server", "client"
    | Client -> "client", "server"
  in
  match f () with
  | `Accept -> Ok ()
  | `Reject with_error ->
    (match with_error with
     | None ->
       Or_error.error_s
         [%message
           (sprintf "%s rejected %s principal or address" me peer)
             ~principal:(peer_principal : Cross_realm_principal_name.t)
             ~address:(peer_address : Async.Socket.Address.Inet.t)]
     | Some error ->
       Or_error.error_s
         [%message
           (sprintf "%s rejected %s principal or address" me peer)
             ~principal:(peer_principal : Cross_realm_principal_name.t)
             ~address:(peer_address : Async.Socket.Address.Inet.t)
             ~reason:(error : Error.t)])
;;

let lift_error = function
  | `Accept -> `Accept
  | `Reject -> `Reject None
;;

let run
      ~(authorize : Authorize.t)
      ~(acting_as : Acting_as.t)
      ~my_principal
      ~peer_address
      ~peer_principal
  =
  let run_sided = run_sided ~acting_as ~peer_address ~peer_principal in
  let open Or_error.Let_syntax in
  let%bind () =
    run_sided (fun () -> validate_cross_realm ~authorize ~my_principal ~peer_principal)
  in
  Or_error.try_with_join (fun () ->
    run_sided (fun () ->
      Authorize.For_internal_use.authorize authorize peer_address peer_principal
      |> lift_error))
;;
