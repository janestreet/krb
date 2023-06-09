open Core
open Async
open Import
module Debug = Internal.Debug

let default_refresh_every = Time.Span.of_min 30.

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
      ; server_cred_cache : (Internal.Cred_cache.t[@sexp.opaque]) option
      ; principal : Cross_realm_principal_name.t
      }
    [@@deriving compare, hash, sexp_of]
  end

  include T
  include Hashable.Make_plain (T)
end

module Extendable_deferred = struct
  open Deferred.Let_syntax

  module Elt = struct
    type t =
      | Never
      | Determinable of unit Deferred.t

    let create = function
      | None -> Never
      | Some wait -> Determinable wait
    ;;

    let wait = function
      | Never -> Deferred.never ()
      | Determinable wait -> wait
    ;;
  end

  type t =
    { defers : Elt.t Deque.t
    ; wait : unit Deferred.t
    }
  [@@deriving fields]

  let create elt ~callback =
    let q = Deque.create () in
    Deque.enqueue_back q (Elt.create elt);
    let rec create_wait () =
      match Deque.dequeue_front q with
      | None ->
        (* [callback] must be called before t.wait is resolved so that we won't have a
           race condition where t.wait is resolved but the removal of that entry in
           [renewal_jobs] is not yet done. *)
        callback ();
        return ()
      | Some elt ->
        let%bind () = Elt.wait elt in
        create_wait ()
    in
    { defers = q; wait = create_wait () }
  ;;

  let push_exn t elt =
    if Deferred.is_determined t.wait
    then failwith "There is a race condition in the implementation of keep valid loop."
    else (
      match Deque.peek_back t.defers with
      | Some Never -> ()
      | None | Some (Determinable _) -> Deque.enqueue_back t.defers (Elt.create elt))
  ;;
end

let renewal_jobs
  : ([ `Wait of unit Or_error.t Ivar.t | `Renewing ] * Extendable_deferred.t)
      Renewal_key.Table.t
  =
  Renewal_key.Table.create ~size:0 ()
;;

let num_active_renewal_jobs () =
  Hashtbl.fold renewal_jobs ~init:0 ~f:(fun ~key:_ ~data:(state, _) count ->
    match state with
    | `Wait _ -> count
    | `Renewing -> count + 1)
;;

let ensure_valid ?keytab ?server_cred_cache ~cred_cache ~valid_for_at_least principal =
  let open Deferred.Or_error.Let_syntax in
  match Internal.Cred_cache.type_ cred_cache with
  | `S4U2Self server_principal ->
    let%bind cred_cache_principal = Cred_cache0.Cross_realm.principal cred_cache in
    let%bind () =
      if Cross_realm_principal_name.equal principal cred_cache_principal
      then return ()
      else
        Deferred.Or_error.error_s
          [%message
            "provided principal doesn't match cred cache principal"
              (principal : Cross_realm_principal_name.t)
              (cred_cache_principal : Cross_realm_principal_name.t)]
    in
    Cred_cache0.Expert.ensure_s4u2self_valid
      ?server_cred_cache
      ~valid_for_at_least
      cred_cache
      (Principal.name server_principal)
  | `Normal ->
    Tgt0.Cross_realm.ensure_valid ?keytab ~cred_cache ~valid_for_at_least principal
;;

let keep_valid_loop ~renewal_key ~refresh_every ~on_error ~aborted =
  let { Renewal_key.cred_cache; keytab; server_cred_cache; principal } = renewal_key in
  let rec loop ?last_failed () =
    let after =
      match last_failed with
      | None -> refresh_every
      (* Try again soon *)
      | Some () -> Time.Span.of_min 2.
    in
    Deferred.choose
      [ Deferred.choice (Clock.after after) (fun () -> `Continue)
      ; Deferred.choice aborted (fun () -> `Finished)
      ]
    >>= function
    | `Finished -> return ()
    | `Continue ->
      (* Give plenty of buffer time before the next job gets called *)
      let valid_for_at_least = Time.Span.(refresh_every + of_min 2.) in
      ensure_valid ?keytab ?server_cred_cache ~cred_cache ~valid_for_at_least principal
      >>= (function
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
          loop ())
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

let keep_valid
      ?(refresh_every = default_refresh_every)
      ?on_error
      ?keytab
      ?server_cred_cache
      ?abort
      ~cred_cache
      principal
  =
  let%bind.Deferred.Or_error () =
    match keytab, server_cred_cache, Internal.Cred_cache.type_ cred_cache with
    | Some _, _, `S4U2Self _ ->
      Deferred.Or_error.error_s
        [%message
          "given a keytab to renew a no-tgt cred cache"
            (principal : Cross_realm_principal_name.t)]
    | _, Some _, `Normal ->
      Deferred.Or_error.error_s
        [%message
          "given a server_cred_cache to renew a tgt cred cache"
            (principal : Cross_realm_principal_name.t)]
    | Some _, _, `Normal | _, Some _, `S4U2Self _ | None, None, _ ->
      Deferred.Or_error.return ()
  in
  let renewal_key = { Renewal_key.cred_cache; keytab; server_cred_cache; principal } in
  let on_error = Option.value on_error ~default:(default_on_error ~renewal_key) in
  match Hashtbl.find renewal_jobs renewal_key with
  | None ->
    let ivar = Ivar.create () in
    let removed = ref false in
    let remove () =
      if not !removed
      then (
        removed := true;
        Hashtbl.remove renewal_jobs renewal_key)
    in
    let extendable_abort =
      Extendable_deferred.create abort ~callback:(fun () -> remove ())
    in
    if not !removed
    then Hashtbl.add_exn renewal_jobs ~key:renewal_key ~data:(`Wait ivar, extendable_abort);
    let%bind result =
      ensure_valid ?keytab ~cred_cache ~valid_for_at_least:refresh_every principal
    in
    Ivar.fill_exn ivar result;
    (match result with
     | Ok () ->
       if not !removed
       then (
         Hashtbl.set renewal_jobs ~key:renewal_key ~data:(`Renewing, extendable_abort);
         don't_wait_for
           (keep_valid_loop
              ~renewal_key
              ~refresh_every
              ~on_error
              ~aborted:(Extendable_deferred.wait extendable_abort)))
     | Error _ -> remove ());
    return result
  | Some (`Wait ivar, curr) ->
    Extendable_deferred.push_exn curr abort;
    Ivar.read ivar
  | Some (`Renewing, curr) ->
    Extendable_deferred.push_exn curr abort;
    Deferred.Or_error.ok_unit
;;

let f = keep_valid
