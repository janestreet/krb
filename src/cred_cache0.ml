open! Core
open! Async
open Import
open Deferred.Or_error.Let_syntax

type t = Internal.Cred_cache.t

let default = Internal.Cred_cache.default

let principal t =
  let%map principal = Internal.Cred_cache.principal t in
  Principal.name principal
;;

let default_principal () =
  let%bind cred_cache = default () in
  principal cred_cache
;;

let in_memory_cred_caches = lazy (Cross_realm_principal_name.Table.create ())

module Cross_realm = struct
  let principal t =
    let%map principal = Internal.Cred_cache.principal t in
    Principal.Cross_realm.name principal
  ;;

  let in_memory_for_principal principal_name =
    let in_memory_cred_caches = Lazy.force in_memory_cred_caches in
    match Hashtbl.find in_memory_cred_caches principal_name with
    | Some (`Ok cred_cache) -> Deferred.Or_error.return cred_cache
    | Some (`Wait ivar) -> Ivar.read ivar
    | None ->
      let ivar = Ivar.create () in
      Hashtbl.add_exn in_memory_cred_caches ~key:principal_name ~data:(`Wait ivar);
      let%bind.Deferred result =
        let%bind principal = Principal.Cross_realm.create principal_name in
        Internal.Cred_cache.create MEMORY principal
      in
      Ivar.fill ivar result;
      (match result with
       | Ok cred_cache ->
         Hashtbl.set in_memory_cred_caches ~key:principal_name ~data:(`Ok cred_cache)
       | Error _ -> Hashtbl.remove in_memory_cred_caches principal_name);
      Deferred.return result
  ;;
end

let in_memory_for_principal principal_name =
  Principal.Name.with_default_realm principal_name >>= Cross_realm.in_memory_for_principal
;;

let mktemp template =
  let%bind tmpfile, fd =
    Deferred.Or_error.try_with
      ~run:
        `Schedule
      ~rest:`Log
      (fun () -> Unix.mkstemp template)
  in
  let%map () = Fd.close fd |> Deferred.ok in
  tmpfile
;;

let initialize_with_creds cred_cache principal all_creds =
  match%bind Internal.Cred_cache.Expert.cache_type cred_cache |> Deferred.ok with
  | FILE ->
    (* From the kerberos source code, [krb5_cc_get_full_name] outputs "TYPE:NAME" *)
    let dst =
      String.chop_prefix_exn
        ~prefix:"FILE:"
        (Internal.Cred_cache.Expert.full_name cred_cache)
    in
    (* Ensure the [rename] occurs with files on the same file system *)
    let%bind src = mktemp dst in
    let%bind cred_cache_staging = Internal.Cred_cache.Expert.resolve ("FILE:" ^ src) in
    let%bind () = Internal.Cred_cache.initialize cred_cache_staging principal in
    let%bind () =
      Deferred.Or_error.List.iter all_creds ~f:(fun creds ->
        Internal.Cred_cache.store cred_cache_staging creds)
    in
    Deferred.Or_error.try_with
      ~run:
        `Schedule
      ~rest:`Log
      (fun () -> Unix.rename ~src ~dst)
  | _ ->
    (* [MEMORY] is the default credential cache. Unfortunately [remove] is not
       implemented, so to avoid growing a cred cache forever, we must call [initialize].
       We make sure [initialize] and [store] occur in a single Async cycle.

       It is still possible to end up with no credentials at all if [store] fails. *)
    Internal.Cred_cache.initialize_and_store cred_cache principal all_creds
;;

let initialize_in_memory_with_creds_from original_cache =
  let%bind name = principal original_cache in
  let%bind new_cache = in_memory_for_principal name in
  let%bind principal = Principal.create name in
  let%bind creds = Internal.Cred_cache.Expert.creds original_cache in
  let%map () = initialize_with_creds new_cache principal creds in
  new_cache
;;

module Expert = struct
  let in_memory_for_principal_with_s4u2self_cred'
        ?client_cred_cache
        ?server_cred_cache
        client_principal
    =
    let%bind () =
      match Option.map client_cred_cache ~f:Internal.Cred_cache.type_ with
      | None | Some (`S4U2Self _) -> return ()
      | Some `Normal ->
        Deferred.Or_error.error_s
          [%message "refusing to put a S4U2Self ticket in a normal cred cache"]
    in
    let%bind server_cred_cache =
      match server_cred_cache with
      | None -> default ()
      | Some t -> return t
    in
    let%bind server_principal = Internal.Cred_cache.principal server_cred_cache in
    let%bind () =
      let client_principal_name = Principal.name client_principal in
      let server_principal_name = Principal.name server_principal in
      if Principal.Name.equal client_principal_name server_principal_name
      then
        Deferred.Or_error.error_s
          [%message
            "Can't get an S4U2Self ticket for yourself - the Kerberos protocol does not \
             allow this. Consider using your existing credentials instead."
              (client_principal_name : Principal.Name.t)
              (server_principal_name : Principal.Name.t)]
      else return ()
    in
    let%bind request =
      Krb_internal_public.Credentials.create
        ~server:server_principal
        ~client:client_principal
        ()
    in
    let%bind client_cred =
      Krb_internal_public.Cred_cache.Expert.get_credentials_for_user
        server_cred_cache
        (* We use [NO_STORE] because this ticket needs to go in a different cred cache.
           The one we use to get the ticket has the wrong principal. *)
        ~flags:[ KRB5_GC_NO_STORE ]
        ~request
    in
    let%bind client_cred_cache =
      match client_cred_cache with
      | Some x -> return x
      | None ->
        Krb_internal_public.Cred_cache.create
          ~type_:(`S4U2Self server_principal)
          MEMORY
          client_principal
    in
    let%bind () =
      initialize_with_creds client_cred_cache client_principal [ client_cred ]
    in
    return client_cred_cache
  ;;

  let in_memory_for_principal_with_s4u2self_cred ?server_cred_cache client_name =
    let%bind client_principal = Principal.create client_name in
    in_memory_for_principal_with_s4u2self_cred' ?server_cred_cache client_principal
  ;;

  let ensure_s4u2self_valid ?valid_for_at_least ?server_cred_cache t server_name =
    let%bind () =
      match Internal.Cred_cache.type_ t with
      | `S4U2Self _ -> return ()
      | `Normal ->
        Deferred.Or_error.error_s
          [%message
            "cannot [ensure_s4u2self_valid] on a cache that didn't originate in \
             [in_memory_for_principal_with_s4u2self_cred]"
              ~cache:(Internal.Cred_cache.Expert.full_name t : string)]
    in
    let%bind server_principal = Principal.create server_name in
    let%bind client_principal = Internal.Cred_cache.principal t in
    let%bind request =
      Internal.Credentials.create ~client:client_principal ~server:server_principal ()
    in
    (* If the ticket is there and valid for [valid_for_at_least], all is well. *)
    match%bind.Deferred
      Internal.Cred_cache.get_credentials
        ?ensure_cached_valid_for_at_least:valid_for_at_least
        ~flags:[ KRB5_GC_CACHED ]
        t
        ~request
    with
    | Ok _ -> return ()
    | Error _ ->
      (* Otherwise, try to renew it. *)
      (match%bind.Deferred
         let%bind old_cred =
           Internal.Cred_cache.get_credentials
             ~ensure_cached_valid_for_at_least:Time.Span.zero
             ~flags:[ KRB5_GC_CACHED ]
             t
             ~request
         in
         let%bind renewed_cred = Internal.Cred_cache.renew t old_cred in
         initialize_with_creds t client_principal [ renewed_cred ]
       with
       | Ok () -> return ()
       | Error _ ->
         (* As a last resort, get a new ticket if possible. *)
         let%bind (_ : t) =
           in_memory_for_principal_with_s4u2self_cred'
             ~client_cred_cache:t
             ?server_cred_cache
             client_principal
         in
         return ())
  ;;
end
