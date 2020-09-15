open Core
open Async
open Import
module Cache_type = Internal.Cache_type
module Credentials = Internal.Credentials
module Debug = Internal.Debug

let default_refresh_every = Time.Span.of_min 30.

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
  Cred_cache.principal cred_cache
  >>=? fun cred_cache_principal_name ->
  if not ([%compare.equal: Principal.Name.t] principal_name cred_cache_principal_name)
  then
    Deferred.Or_error.error_s
      [%message
        "The cred cache's principal does not match the supplied principal"
          (principal_name : Principal.Name.t)
          (cred_cache_principal_name : Principal.Name.t)]
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
  Principal.create principal
  >>=? fun principal ->
  Keytab.validate keytab principal >>=? fun () -> Credentials.of_keytab principal keytab
;;

let get_from_default_cred_cache ?valid_for_at_least principal =
  Cred_cache.default ()
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
  >>=? fun tgt' -> return (check_expiration ?valid_for_at_least tgt') >>|? fun () -> tgt'
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
  Principal.create principal
  >>=? fun principal -> Cred_cache.initialize_with_creds cred_cache principal [ creds ]
;;

let ensure_valid ?valid_for_at_least ?keytab ~cred_cache principal =
  check_valid ~cred_cache ?valid_for_at_least principal
  >>= function
  | Ok () -> Deferred.Or_error.ok_unit
  | Error e ->
    initialize_with_tgt ?valid_for_at_least ?keytab ~cred_cache principal
    >>| Result.map_error ~f:(fun e2 -> Error.of_list [ e; e2 ])
;;

let handle_on_error on_error e =
  match on_error with
  | `Ignore -> ()
  | `Raise -> Error.raise e
  | `Call f -> f e
;;

module Renewal_key = struct
  module T = struct
    type t =
      { cred_cache : (Internal.Cred_cache.t[@sexp.opaque])
      ; keytab : Keytab.Path.t option
      ; principal : Principal.Name.t
      }
    [@@deriving compare, hash, sexp_of]
  end

  include T
  include Hashable.Make_plain (T)
end

let renewal_jobs : [ `Wait of unit Or_error.t Ivar.t | `Renewing ] Renewal_key.Table.t =
  Renewal_key.Table.create ~size:0 ()
;;

let keep_valid_indefinitely_loop ~renewal_key ~refresh_every ~on_error =
  let { Renewal_key.cred_cache; keytab; principal } = renewal_key in
  let rec loop ?last_failed () =
    let after =
      match last_failed with
      | None -> refresh_every
      (* Try again soon *)
      | Some () -> Time.Span.of_min 2.
    in
    Clock.after after
    >>= fun () ->
    (* Give plenty of buffer time before the next job gets called *)
    let valid_for_at_least = Time.Span.(refresh_every + of_min 2.) in
    ensure_valid ?keytab ~cred_cache ~valid_for_at_least principal
    >>= function
    | Error error ->
      Debug.log_s (fun () ->
        [%message
          "Error renewing Kerberos credentials"
            (error : Error.t)
            ~_:(renewal_key : Renewal_key.t)]);
      handle_on_error on_error error;
      loop ~last_failed:() ()
    | Ok () ->
      Debug.log_s (fun () ->
        [%message
          "Ensured Kerberos credentials valid"
            (valid_for_at_least : Time.Span.t)
            ~_:(renewal_key : Renewal_key.t)]);
      loop ()
  in
  loop ()
;;

let default_on_error ~renewal_key =
  `Call
    (fun error ->
       Log.Global.error_s
         [%message
           "Error renewing Kerberos credentials"
             (renewal_key : Renewal_key.t)
             (error : Error.t)])
;;

let keep_valid_indefinitely
      ?(refresh_every = default_refresh_every)
      ?on_error
      ?keytab
      ~cred_cache
      principal
  =
  let renewal_key = { Renewal_key.cred_cache; keytab; principal } in
  let on_error = Option.value on_error ~default:(default_on_error ~renewal_key) in
  match Hashtbl.find renewal_jobs renewal_key with
  | None ->
    let ivar = Ivar.create () in
    Hashtbl.add_exn renewal_jobs ~key:renewal_key ~data:(`Wait ivar);
    let%bind result =
      ensure_valid ?keytab ~cred_cache ~valid_for_at_least:refresh_every principal
    in
    Ivar.fill ivar result;
    (match result with
     | Ok () ->
       Hashtbl.set renewal_jobs ~key:renewal_key ~data:`Renewing;
       don't_wait_for (keep_valid_indefinitely_loop ~renewal_key ~refresh_every ~on_error)
     | Error _ -> Hashtbl.remove renewal_jobs renewal_key);
    return result
  | Some (`Wait ivar) -> Ivar.read ivar
  | Some `Renewing -> Deferred.Or_error.ok_unit
;;

let initialize_in_new_cred_cache ?(cache_type = Cache_type.MEMORY) ?keytab principal_name =
  Principal.create principal_name
  >>=? fun principal ->
  Internal.Cred_cache.create cache_type principal
  >>=? fun cred_cache ->
  ensure_valid ?keytab ~cred_cache principal_name >>|? fun () -> cred_cache
;;
