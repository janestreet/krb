open! Core
open Async


type t = Context.t Throttle.Sequencer.t

let the_t : t Lazy_deferred.t =
  Lazy_deferred.create (fun () ->
    (* Before calling down into libkrb5, we release the OCaml runtime. We do our calls in
       another thread, so it is possible for caml_sys_exit to be initiated while we are
       still doing Kerberos things. Because libkrb5 is dynamically linked, this can cause
       undefined behavior, most often segfaults or assertion failures.

       We make sure all outstanding calls (including the [Context.init] call) are
       completed before letting Async shutdown complete.

       Because [shutdown] only calls the handlers that have been registered at the time
       that [shutdown] is called, we have to be careful not to call [Context.init] if we
       are already shutting down. *)
    if Shutdown.is_shutting_down ()
    then
      failwith
        "Not initializing global Kerberos context because async is already shutting down";
    Krb_debug.log_s (fun () -> [%message "Initializing global Kerberos context"]);
    let context_initialized = Ivar.create () in
    Shutdown.don't_finish_before (Ivar.read context_initialized);
    let%map t =
      In_thread.run Context.init
      >>| (fun result ->
        Ivar.fill context_initialized ();
        result)
      >>| Result.map_error ~f:(fun code ->
        let krb_error = Krb_error.to_string ~info:"krb5_init_context" code in
        match Krb_info.sandbox_tag with
        | Some tag ->
          Error.create_s
            [%message
              "Failed to initialize global Krb context"
                ~_:(krb_error : string)
                (code : int32)
                (tag : Sexp.t)]
        | None ->
          Error.create_s
            [%message
              "Failed to initialize global Krb context"
                ~_:(krb_error : string)
                (code : int32)])
      >>| ok_exn
      >>| Throttle.Sequencer.create
    in
    Shutdown.at_shutdown (fun () ->
      Throttle.prior_jobs_done t
      );
    t)
;;

(* This is the monitor that we run in when calling [Gc.add_finalizer]. [Gc.add_finalizer]
   stores a reference to the current monitor. Because finalizers are GC roots, this
   prevents the monitor from being GC'd until the finalizer is caller. It isn't too
   difficult to get yourself into a situation where the monitor holds a reference to the
   thing you are adding a finalizer for. When this happens, the finalizer will never run
   and the monitor will never be GC'd.

   To make the above a bit more concrete, take a look at
   lib/krb/jane/test/bin/finalizer_memory_leak.ml *)
let finalizer_monitor =
  lazy
    (let monitor = Monitor.create ~name:"Krb.Context_sequencer" () in
     (* We have to detach the monitor so it doesn't hold onto a reference to it's parent
        monitor (i.e. the current monitor when this lazy is forced). We don't expect any
        of the finalizers to raise, nor do we really have anything useful to do with the
        exception, so we just ignore it. *)
     Monitor.detach_and_iter_errors monitor ~f:(ignore : exn -> unit);
     monitor)
;;

(* This will raise if [f] raises or if forcing [the_t] raises. The latter can happen if
   you are in the kerberos sandbox. *)
let enqueue_job_internal_exn ~f =
  Lazy_deferred.force_exn the_t >>= fun t -> Throttle.enqueue t (fun c -> f c)
;;

let enqueue_job_internal_krb_result ~f =
  match%bind Lazy_deferred.force the_t with
  | Error error -> Deferred.Result.fail (`Raised error)
  | Ok t ->
    (match%bind Throttle.enqueue' t (fun c -> f c) with
     | `Aborted -> assert false (* We don't call [Throttle.abort] *)
     | `Raised exn -> Deferred.Result.fail (`Raised (Error.of_exn exn))
     | `Ok (Ok res) -> return (Ok res)
     | `Ok (Error code) -> Deferred.Result.fail (`Krb_error code))
;;

let enqueue_job_exn ~f =
  enqueue_job_internal_exn ~f:(fun c -> In_thread.run (fun () -> f c))
;;

let gen_error_msg ~enqueue ~(info : _ Krb_info.t) code =
  let%bind krb_error =
    enqueue ~f:(fun context -> Krb_error.to_string ~context ~info:info.function_ code)
  in
  match%map Krb_info.tags info code with
  | None -> Error.create_s [%message "" ~_:(krb_error : string)]
  | Some tags -> Error.create_s [%message "" ~_:(krb_error : string) ~_:(tags : Sexp.t)]
;;

let debug_before_job ~(info : _ Krb_info.t) ~is_blocking () =
  Krb_debug.log_s (fun () ->
    match info.tag_arguments with
    | None ->
      [%message
        "Calling Kerberos function" ~info:(info.function_ : string) (is_blocking : bool)]
    | Some tags ->
      let tags = Lazy.force tags in
      [%message
        "Calling Kerberos function"
          ~info:(info.function_ : string)
          (is_blocking : bool)
          (tags : Sexp.t)])
;;

let debug_after_job ~(info : 'a Krb_info.t) result =
  Krb_debug.log_s (fun () ->
    let tags =
      match result, info.tag_result with
      | Ok result, Some get_tags -> Some (get_tags result)
      | Ok _, None -> None
      | Error error, _ -> Some ([%sexp_of: Error.t] error)
    in
    match tags with
    | None -> [%message "Called Kerberos function" ~info:(info.function_ : string)]
    | Some tags ->
      [%message
        "Called Kerberos function" ~info:(info.function_ : string) (tags : Sexp.t)])
;;

let enqueue_job_with_info_aux ~info ~error_msg ~is_blocking ~f =
  debug_before_job ~info ~is_blocking ();
  match%bind enqueue_job_internal_krb_result ~f with
  | Ok result ->
    debug_after_job ~info (Ok result);
    return (Ok result)
  | Error (`Raised _ as raised) -> Deferred.Result.fail raised
  | Error (`Krb_error code) ->
    let%bind error = error_msg ~info code in
    debug_after_job ~info (Error error);
    Deferred.Result.fail (`Krb_error (error, code))
;;

let error_msg_non_blocking ~info code = gen_error_msg ~enqueue:enqueue_job_exn ~info code

let enqueue_job_with_info' ~info ~f =
  enqueue_job_with_info_aux
    ~info
    ~error_msg:error_msg_non_blocking
    ~is_blocking:false
    ~f:(fun c -> In_thread.run (fun () -> f c))
;;

let enqueue_job_with_info ~info ~f =
  enqueue_job_with_info' ~info ~f
  |> Deferred.Result.map_error ~f:(function
    | `Raised error -> error
    | `Krb_error (error, _code) -> error)
;;

let add_finalizer arg ~f:finalize =
  Scheduler.within ~monitor:(force finalizer_monitor) (fun () ->
    Gc.add_finalizer_exn arg (fun arg ->
      don't_wait_for (enqueue_job_exn ~f:(fun c -> finalize c arg))))
;;

module Expert = struct
  let enqueue_job_blocking_exn ~f = enqueue_job_internal_exn ~f:(fun c -> return (f c))

  let error_msg_blocking ~info code =
    gen_error_msg ~enqueue:enqueue_job_blocking_exn ~info code
  ;;

  let enqueue_job_with_info_blocking ~info ~f =
    enqueue_job_with_info_aux
      ~info
      ~error_msg:error_msg_blocking
      ~is_blocking:true
      ~f:(fun c -> return (f c))
    |> Deferred.Result.map_error ~f:(function
      | `Raised error -> error
      | `Krb_error (error, _code) -> error)
  ;;
end

(* Payloads up to this threshold will be encrypted on the main thread,
   blocking Async. Anything above this threshold will be encrypted on a separate thread.
   This was chosen somewhat arbitrarily based on benchmark results. An
   encryption/decryption roundtrip for a 1MB payload is around 60ms. *)
let threshold_for_blocking_encryption = 1024 * 1024

let enqueue_blocking_if_below_encryption_size_threshold ~data_size =
  if data_size <= threshold_for_blocking_encryption
  then Expert.enqueue_job_with_info_blocking
  else enqueue_job_with_info
;;
