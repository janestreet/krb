open! Core
open Async
open Env_config
module Debug_log = Log.Make_global ()

let initialized_log : [ `Initialized ] Set_once.t = Set_once.create ()

let maybe_initialize_log () =
  match Set_once.get initialized_log with
  | Some `Initialized -> ()
  | None ->
    Set_once.set_exn initialized_log [%here] `Initialized;
    let output = List.map Config.debug_log_config ~f:Log_output.to_output in
    Debug_log.set_output output
;;

let log_s f =
  if Config.print_debug_messages
  then (
    maybe_initialize_log ();
    Debug_log.sexp (f ()))
;;
