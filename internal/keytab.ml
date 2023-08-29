open! Core
open Async

module Raw = struct
  type t
  type keytab = t

  module Cursor = struct
    type t

    external create : Context.t -> keytab -> t Krb_result.t = "caml_krb5_kt_start_seq_get"

    external advance
      :  Context.t
      -> keytab
      -> t
      -> Keytab_entry.t option Krb_result.t
      = "caml_krb5_kt_next_entry"

    external free
      :  Context.t
      -> keytab
      -> t
      -> unit Krb_result.t
      = "caml_krb5_kt_end_seq_get"
  end

  external resolve : Context.t -> string -> t Krb_result.t = "caml_krb5_kt_resolve"
  external free : Context.t -> t -> unit = "caml_krb5_kt_close"

  external add_entry
    :  Context.t
    -> t
    -> Keytab_entry.t
    -> unit Krb_result.t
    = "caml_krb5_kt_add_entry"

  external remove_entry
    :  Context.t
    -> t
    -> Keytab_entry.t
    -> unit Krb_result.t
    = "caml_krb5_kt_remove_entry"
end

type t =
  { raw : Raw.t
  ; path : string
  }
[@@deriving fields ~getters]

let sexp_of_t t = [%sexp { path = (t.path : string Sexp_opaque_when_testing.t) }]
let to_raw = raw

let load path =
  let tag_arguments = lazy [%message (path : string)] in
  let info = Krb_info.create ~tag_arguments "[krb5_kt_resolve]" in
  Context_sequencer.enqueue_job_with_info ~info ~f:(fun c -> Raw.resolve c path)
  >>|? fun raw ->
  Context_sequencer.add_finalizer raw ~f:Raw.free;
  { raw; path }
;;

let add_entry t entry =
  let tag_arguments = lazy [%message "" ~keytab:(t : t)] in
  let info = Krb_info.create ~tag_arguments "[krb5_kt_add_entry]" in
  Context_sequencer.enqueue_job_with_info ~info ~f:(fun c -> Raw.add_entry c t.raw entry)
;;

let remove_entry t entry =
  let tag_arguments = lazy [%message "" ~keytab:(t : t)] in
  let info = Krb_info.create ~tag_arguments "[krb5_kt_remove_entry]" in
  Context_sequencer.enqueue_job_with_info ~info ~f:(fun c ->
    Raw.remove_entry c t.raw entry)
;;

module Keytab_cursor = Cursor.Make (struct
    module Container = struct
      type raw = Raw.t
      type nonrec t = t [@@deriving sexp_of]

      let tag t = [%message "" ~keytab:(t : t)]
      let to_raw = to_raw
    end

    module Item = struct
      type raw = Keytab_entry.t
      type t = raw

      let of_raw = Deferred.Or_error.return
      let free = Keytab_entry.Raw.free
    end

    module Cursor = struct
      type t = Raw.Cursor.t

      let start = Raw.Cursor.create
      let advance = Raw.Cursor.advance
      let finish = Raw.Cursor.free
    end

    let info = "[krb5_kt_start_seq_get//krb5_kt_next_entry//krb5_kt_end_seq_get]"
  end)

let entries t = Keytab_cursor.get_all t
