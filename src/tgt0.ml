open Core
open Async
open Import
module Cache_type = Internal.Cache_type
module Credentials = Internal.Credentials

module Cross_realm = struct
  (* empirically it seems tgts must be valid for more than 122 seconds. *)
  let check_expiration ?(valid_for_at_least = Time.Span.of_min 10.) tgt =
    let tgt_expiration = Credentials.endtime tgt in
    let time_now = Time.now () in
    if Time.(add time_now valid_for_at_least >= tgt_expiration)
    then
      Or_error.error_s
        [%message
          "The cred cache's tgt expires too soon"
            ~should_be_valid_for_at_least:(valid_for_at_least : Time.Span.t)
            (tgt_expiration : Time.t)
            (time_now : Time.t)]
    else Ok ()
  ;;

  let get_cached_tgt ?valid_for_at_least ~cred_cache principal_name =
    Cred_cache0.Cross_realm.principal cred_cache
    >>=? fun cred_cache_principal_name ->
    if not
         ([%compare.equal: Cross_realm_principal_name.t]
            principal_name
            cred_cache_principal_name)
    then
      Deferred.Or_error.error_s
        [%message
          "The cred cache's principal does not match the supplied principal"
            (principal_name : Cross_realm_principal_name.t)
            (cred_cache_principal_name : Cross_realm_principal_name.t)]
    else
      Internal.Cred_cache.get_cached_tgt
        ?ensure_valid_for_at_least:valid_for_at_least
        cred_cache
  ;;

  let check_valid ?valid_for_at_least ~cred_cache principal_name =
    get_cached_tgt ?valid_for_at_least ~cred_cache principal_name
    >>|? fun (_ : Internal.Credentials.t) -> ()
  ;;

  let get_from_keytab ~keytab principal =
    Keytab.load keytab
    >>=? fun keytab ->
    Principal.Cross_realm.create principal
    >>=? fun principal ->
    Keytab.validate keytab principal >>=? fun () -> Credentials.of_keytab principal keytab
  ;;

  let get_from_default_cred_cache ?valid_for_at_least principal =
    Cred_cache0.default ()
    >>=? fun default_cred_cache ->
    get_cached_tgt ?valid_for_at_least ~cred_cache:default_cred_cache principal
  ;;

  let get_from_renewal ?valid_for_at_least ~cred_cache principal =
    (* Intentionally don't pass along [valid_for_at_least] to [get_cached_tgt] - we don't
       care how long it is valid for because we're going to immediately renew it. Instead,
       we check the time of the credentials after renewal. *)
    get_cached_tgt ~valid_for_at_least:Time.Span.zero ~cred_cache principal
    >>=? fun tgt ->
    Internal.Cred_cache.renew cred_cache tgt
    >>=? fun tgt' ->
    return (check_expiration ?valid_for_at_least tgt') >>|? fun () -> tgt'
  ;;

  let get_tgt ?valid_for_at_least ?keytab ~cred_cache principal =
    let sources =
      [ Some ("default cred cache", get_from_default_cred_cache ?valid_for_at_least)
      ; Option.map keytab ~f:(fun keytab -> "keytab", get_from_keytab ~keytab)
      ; Some ("renewal", get_from_renewal ?valid_for_at_least ~cred_cache)
      ]
      |> List.filter_opt
    in
    let%map result =
      Deferred.Or_error.find_map_ok sources ~f:(fun (source, get) ->
        get principal >>| Or_error.tag ~tag:(sprintf "while getting TGT from %s" source))
    in
    match result with
    | Error _ when not Config.verbose_errors ->
      Or_error.errorf
        "Unable to acquire new TGT from any of %s. You can enable more verbose error \
         messages with OCAML_KRB_CONFIG."
        (List.map sources ~f:fst |> String.concat ~sep:", ")
    | _ -> result
  ;;

  let initialize_with_tgt ?valid_for_at_least ?keytab ~cred_cache principal =
    get_tgt ?valid_for_at_least ?keytab ~cred_cache principal
    >>=? fun creds ->
    Principal.Cross_realm.create principal
    >>=? fun principal -> Cred_cache0.initialize_with_creds cred_cache principal [ creds ]
  ;;

  let ensure_valid ?valid_for_at_least ?keytab ~cred_cache principal =
    check_valid ~cred_cache ?valid_for_at_least principal
    >>= function
    | Ok () -> Deferred.Or_error.ok_unit
    | Error e ->
      initialize_with_tgt ?valid_for_at_least ?keytab ~cred_cache principal
      >>| Result.map_error ~f:(fun e2 -> Error.of_list [ e; e2 ])
  ;;

  let initialize_in_new_cred_cache
    ?(cache_type = Cache_type.MEMORY)
    ?keytab
    principal_name
    =
    Principal.Cross_realm.create principal_name
    >>=? fun principal ->
    Internal.Cred_cache.create cache_type principal
    >>=? fun cred_cache ->
    ensure_valid ?keytab ~cred_cache principal_name >>|? fun () -> cred_cache
  ;;
end

open Deferred.Or_error.Let_syntax

let check_valid ?valid_for_at_least ~cred_cache principal_name =
  Principal.Name.with_default_realm principal_name
  >>= Cross_realm.check_valid ?valid_for_at_least ~cred_cache
;;

let ensure_valid ?valid_for_at_least ?keytab ~cred_cache principal =
  Principal.Name.with_default_realm principal
  >>= Cross_realm.ensure_valid ?valid_for_at_least ?keytab ~cred_cache
;;

let initialize_in_new_cred_cache ?cache_type ?keytab principal_name =
  Principal.Name.with_default_realm principal_name
  >>= Cross_realm.initialize_in_new_cred_cache ?cache_type ?keytab
;;

let get_cached_tgt ?valid_for_at_least ~cred_cache principal_name =
  Principal.Name.with_default_realm principal_name
  >>= Cross_realm.get_cached_tgt ?valid_for_at_least ~cred_cache
;;
