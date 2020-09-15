open! Core
open Async

type t

module Raw = struct
  external create
    :  Context.t
    -> Principal.Raw.t
    -> kvno:int
    -> Keyblock.t
    -> t Krb_result.t
    = "caml_krb5_create_keytab_entry"

  external kvno : t -> int = "caml_krb5_keytab_entry_get_kvno"

  external principal
    :  Context.t
    -> t
    -> Principal.Raw.t Krb_result.t
    = "caml_krb5_keytab_entry_get_principal"

  external keyblock
    :  Context.t
    -> t
    -> Keyblock.t Krb_result.t
    = "caml_krb5_keytab_entry_get_keyblock"

  external free : Context.t -> t -> unit = "caml_krb5_free_keytab_entry"
end

let create principal ~kvno keyblock =
  let tag_arguments = lazy [%message (principal : Principal.t) (kvno : int)] in
  let info =
    Krb_info.create ~tag_arguments "[krb5_timeofday//krb5_create_keytab_entry]"
  in
  Context_sequencer.enqueue_job_with_info ~info ~f:(fun c ->
    Raw.create c (Principal.to_raw principal) ~kvno keyblock)
  >>|? fun t ->
  Context_sequencer.add_finalizer t ~f:Raw.free;
  t
;;

let kvno t = Raw.kvno t

let principal t =
  let info = Krb_info.create "[krb5_keytab_entry_get_principal]" in
  Context_sequencer.enqueue_job_with_info ~info ~f:(fun c -> Raw.principal c t)
  >>=? fun principal ->
  Context_sequencer.add_finalizer principal ~f:Principal.Raw.free;
  Principal.of_raw principal
;;

let keyblock t =
  let info = Krb_info.create "[krb5_keytab_entry_get_keyblock]" in
  Context_sequencer.enqueue_job_with_info ~info ~f:(fun c -> Raw.keyblock c t)
  >>|? fun keyblock ->
  Context_sequencer.add_finalizer keyblock ~f:Keyblock.Raw.free;
  keyblock
;;
