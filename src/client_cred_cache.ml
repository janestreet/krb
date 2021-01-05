open! Core
open Async
open Import

type t =
  | Single_cache of Internal.Cred_cache.t
  | Double_cache of
      { memory_cache : Internal.Cred_cache.t
      ; default_cache : Internal.Cred_cache.t
      }
[@@deriving sexp_of]

let cred_cache = function
  | Single_cache cache -> cache
  | Double_cache { memory_cache; default_cache = _ } -> memory_cache
;;

let of_cred_cache cred_cache =
  let open Deferred.Or_error.Let_syntax in
  let%bind principal = Cred_cache.principal cred_cache in
  let%bind () = Tgt.ensure_valid ~cred_cache ~keytab:User principal in
  return (Single_cache cred_cache)
;;

let in_memory () =
  let%bind principal =
    match%bind Cred_cache.default_principal () with
    | Ok principal -> return principal
    | Error _ ->
      let%bind username = Currently_running_user.name () in
      return (Principal.Name.User username)
  in
  let open Deferred.Or_error.Let_syntax in
  let%bind memory_cache = Cred_cache.in_memory_for_principal principal in
  let%bind default_cache = Internal.Cred_cache.default () in
  let%bind () =
    Tgt.keep_valid_indefinitely ~cred_cache:memory_cache ~keytab:User principal
  in
  return (Double_cache { memory_cache; default_cache })
;;

let get_cached ~flags cred_cache ~request =
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
;;

let get_credentials ~flags t ~request =
  let open Deferred.Or_error.Let_syntax in
  let with_default_cache_error error d =
    Deferred.Or_error.map d ~f:(fun x -> x, `Error_getting_creds_from_default_cache error)
  in
  match t with
  | Single_cache cred_cache ->
    (* The [Client_cred_cache] wrapper does nothing. Just call [get_credentials]. *)
    Internal.Cred_cache.get_credentials ~flags cred_cache ~request
    |> with_default_cache_error None
  | Double_cache { memory_cache; default_cache } ->
    (* First check to see if we have this ticket already cached in the memory cred cache.
    *)
    (match%bind get_cached ~flags memory_cache ~request with
     | Some cred -> return cred |> with_default_cache_error None
     | None ->
       (* Next, try to get a ticket from the default cache. Either this ticket is cached
          already or, if there is a TGT, we will talk to the KDC to get a ticket. Either
          way, if this is successful, the default cache will have this ticket. *)
       (match%bind.Deferred
          Internal.Cred_cache.get_credentials ~flags default_cache ~request
        with
        | Ok cred ->
          (* Save this ticket into the memory cache *)
          let%bind () =
            Internal.Cred_cache.store_if_not_in_cache memory_cache ~request cred
          in
          return cred |> with_default_cache_error None
        | Error error ->
          (* Most likely this means that the default cred cache doesn't exist or doesn't
             have a TGT. We try to get a ticket using the memory cache. We don't bother
             saving the ticket back into the default cache because that cache already
             doesn't have a TGT, so something strange is probably happening. *)
          Internal.Cred_cache.get_credentials ~flags memory_cache ~request
          |> with_default_cache_error (Some error)))
;;

module For_testing = struct
  let create ~memory_cache ~default_cache = Double_cache { memory_cache; default_cache }

  let cred_caches = function
    | Single_cache cache -> [ cache ]
    | Double_cache { memory_cache; default_cache } -> [ memory_cache; default_cache ]
  ;;
end
