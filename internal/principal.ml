open! Core
open Async

module Raw = struct
  type t

  external of_string : Context.t -> string -> t Krb_result.t = "caml_krb5_parse_name"
  external to_string : Context.t -> t -> string Krb_result.t = "caml_krb5_unparse_name"
  external free : Context.t -> t -> unit = "caml_krb5_free_principal"
  external salt : Context.t -> t -> Data.t Krb_result.t = "caml_krb5_principal2salt"
  external realm : t -> string = "caml_krb5_princ_realm"
  external is_config_principal : Context.t -> t -> bool = "caml_krb5_is_config_principal"
end

type t =
  { raw : Raw.t
  ; realm : string
  ; principal : string
  }
[@@deriving fields]

let sexp_of_t t =
  [%sexp { realm = (t.realm : string); principal = (t.principal : string) }]
;;

let to_raw = raw

let of_raw raw =
  let info = Krb_info.create "[krb5_unparse_name]" in
  Context_sequencer.enqueue_job_with_info ~info ~f:(fun c -> Raw.to_string c raw)
  >>|? fun principal ->
  let realm = Raw.realm raw in
  { raw; principal; realm }
;;

let of_string name =
  let tag_arguments = lazy [%message "" name] in
  let info = Krb_info.create ~tag_arguments "[krb5_parse_name]" in
  Context_sequencer.enqueue_job_with_info ~info ~f:(fun c -> Raw.of_string c name)
  >>=? fun principal ->
  Context_sequencer.add_finalizer principal ~f:Raw.free;
  of_raw principal
;;

let to_string = principal

let salt t =
  let tag_arguments = lazy [%message "" ~principal:(t : t)] in
  let info = Krb_info.create ~tag_arguments "[krb5_principal2salt]" in
  Context_sequencer.enqueue_job_with_info ~info ~f:(fun c -> Raw.salt c t.raw)
  >>|? fun salt ->
  Context_sequencer.add_finalizer salt ~f:Data.free;
  salt
;;
