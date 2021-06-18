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
