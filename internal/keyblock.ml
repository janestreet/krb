open! Core
open Async

module Raw = struct
  type t

  external enctype : t -> int = "caml_krb5_keyblock_get_enctype"
  external key : t -> string = "caml_krb5_keyblock_get_key"

  external of_password
    :  Context.t
    -> enctype:int
    -> string
    -> salt:Data.t
    -> t Krb_result.t
    = "caml_krb5_c_string_to_key"

  external create_from_key_data
    :  Context.t
    -> enctype:int
    -> Bigstring.t
    -> t Krb_result.t
    = "caml_krb5_create_keyblock_from_key_data"

  external c_decrypt
    :  Context.t
    -> t
    -> usage:int
    -> enctype:int
    -> kvno:int
    -> Bigsubstring.t
    -> Bigstring.t Krb_result.t
    = "caml_krb5_c_decrypt_bytecode" "caml_krb5_c_decrypt_native"

  external free : Context.t -> t -> unit = "caml_krb5_free_keyblock"
end

module T = struct
  type t = Raw.t

  let create enctype ~password ~salt =
    let tag_arguments = lazy [%message (enctype : Enctype.t)] in
    let enctype = Enctype.to_int enctype in
    let info = Krb_info.create ~tag_arguments "[krb5_c_string_to_key]" in
    Context_sequencer.enqueue_job_with_info ~info ~f:(fun c ->
      Raw.of_password c ~enctype password ~salt)
    >>|? fun keyblock ->
    Context_sequencer.add_finalizer keyblock ~f:Raw.free;
    keyblock
  ;;

  let create_from_key_data ~enctype key_data =
    let info = Krb_info.create "[krb5_create_keyblock_from_key_data]" in
    let enctype = Enctype.to_int enctype in
    Context_sequencer.enqueue_job_with_info ~info ~f:(fun c ->
      Raw.create_from_key_data c ~enctype key_data)
    >>|? fun keyblock ->
    Context_sequencer.add_finalizer keyblock ~f:Raw.free;
    keyblock
  ;;

  let decrypt t ~usage ~enctype ~kvno data =
    let info = Krb_info.create "[krb5_c_decrypt]" in
    let usage = Key_usage_number.to_int usage in
    let enctype = Enctype.to_int enctype in
    Context_sequencer.enqueue_blocking_if_below_encryption_size_threshold
      ~data_size:(Bigsubstring.length data)
      ~info
      ~f:(fun c -> Raw.c_decrypt c t ~usage ~enctype ~kvno data)
  ;;

  (* observable view of a keyblock *)

  let enctype t = Raw.enctype t |> Enctype.of_int
  let key t = Raw.key t |> Hex_encode.to_hex ~case:`Lowercase |> fun s -> "0x" ^ s

  module Obs = struct
    type t =
      { enctype : Enctype.t
      ; key : string
      }
    [@@deriving compare, fields ~iterators:create, sexp_of]
  end

  let obs t = Obs.Fields.create ~enctype:(enctype t) ~key:(key t)
  let compare t t' = [%compare: Obs.t] (obs t) (obs t')
  let sexp_of_t t = [%sexp_of: Obs.t] (obs t)
end

include T
include Comparable.Make_plain (T)
