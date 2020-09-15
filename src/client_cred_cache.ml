open! Core
open Async
open Import

type t =
  { cred_cache : Internal.Cred_cache.t
  ; default_to_store_service_tickets : Internal.Cred_cache.t option
  }
[@@deriving fields, sexp_of]

let of_cred_cache cred_cache = { cred_cache; default_to_store_service_tickets = None }

let in_memory () =
  let%bind principal =
    match%bind Cred_cache.default_principal () with
    | Ok principal -> return principal
    | Error _ ->
      let%bind username = Currently_running_user.name () in
      return (Principal.Name.User username)
  in
  let open Deferred.Or_error.Let_syntax in
  let%bind cred_cache = Cred_cache.in_memory_for_principal principal in
  let%bind default = Internal.Cred_cache.default () in
  Deferred.Or_error.return { cred_cache; default_to_store_service_tickets = Some default }
;;

let store_in_cred_cache cred_cache ~request ~credentials =
  (* We try to avoid storing the same credentials more than once. It is still possible
     if there are concurrent calls to this function, oh well. *)
  Internal.Cred_cache.get_credentials
    ~tag_error_with_all_credentials:false
    ~flags:[ Internal.Krb_flags.Get_credentials.KRB5_GC_CACHED ]
    cred_cache
    ~request
  >>| Result.is_ok
  >>= fun already_cached ->
  if not already_cached
  then Internal.Cred_cache.store cred_cache credentials
  else Deferred.Or_error.ok_unit
;;

(* The places in which we look for creds are, in priority order:

   1) cached in [cred_cache]
   2) cached in [default_to_store_service_tickets]
   3) from the KDC

   This is much like what happens if you just use [cred_cache], with one extra layer of
   caching before we talk to the KDC if we have a [default_to_store_service_tickets].
*)
let get_credentials ~flags t ~request =
  let open Deferred.Or_error.Let_syntax in
  let%bind credentials, where_to_save =
    let get_cached cred_cache =
      let open Deferred.Let_syntax in
      match%bind
        Internal.Cred_cache.get_credentials
          ~tag_error_with_all_credentials:false
          cred_cache
          ~request
          ~flags:(Internal.Krb_flags.Get_credentials.KRB5_GC_CACHED :: flags)
      with
      | Ok x -> return (Ok (Some x))
      | Error _ -> return (Ok None)
    in
    let%bind cached =
      match t.default_to_store_service_tickets with
      | None ->
        (* If there's no [default_to_store_service_tickets], don't bother checking for
           cached credentials separately; [get_credentials] will do the right thing. *)
        return None
      | Some default_cache ->
        (match%bind get_cached t.cred_cache with
         | Some cred -> return (Some cred)
         | None -> get_cached default_cache)
    in
    match cached with
    | Some cred -> return (cred, `Nowhere)
    | None ->
      let%bind cred = Internal.Cred_cache.get_credentials ~flags t.cred_cache ~request in
      return (cred, `To_default_cache)
  in
  match t.default_to_store_service_tickets, where_to_save with
  | Some _, `Nowhere | None, _ ->
    return (credentials, `Error_storing_in_default_cache None)
  | Some default_cred_cache, `To_default_cache ->
    let open Deferred.Let_syntax in
    let%bind error =
      store_in_cred_cache default_cred_cache ~request ~credentials >>| Result.error
    in
    Deferred.Or_error.return (credentials, `Error_storing_in_default_cache error)
;;
