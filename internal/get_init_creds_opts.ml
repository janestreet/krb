open! Core
open Async

module Raw = struct
  type t

  (* The order of these arguments must agree with raw_stubs.c. *)
  external create
    :  Context.t
    -> int (* tkt_lifetime *)
    -> int (* renew_lifetime *)
    -> bool (* forwardable *)
    -> bool (* proxiable *)
    -> t Krb_result.t
    = "caml_krb5_get_init_creds_opt_alloc"

  external free : Context.t -> t -> unit = "caml_krb5_get_init_creds_opt_free"
end

type t =
  { tkt_lifetime : Time_float.Span.t
  ; renew_lifetime : Time_float.Span.t
  ; forwardable : bool
  ; proxiable : bool
  }
[@@deriving sexp_of]

let default =
  { tkt_lifetime =
      Time_float.Span.of_hr 10.
  (* setting renew_lifetime leads to the KDC issuing renewable tickets. By specifying a
     very long renew_lifetime, we get tickets with the max allowed renew time. By always
     obtaining a renewable TGT, we ensure that all service tickets acquired via that TGT
     are also renewable. *)
  ; renew_lifetime = Time_float.Span.of_day 365.
  ; forwardable =
      true
  ; proxiable = false
  }
;;

let create
      ?(tkt_lifetime = default.tkt_lifetime)
      ?(renew_lifetime = default.renew_lifetime)
      ?(forwardable = default.forwardable)
      ?(proxiable = default.proxiable)
      ()
  =
  { tkt_lifetime; renew_lifetime; forwardable; proxiable }
;;

let to_raw t =
  let tag_arguments = lazy [%message "" ~_:(t : t)] in
  let info = Krb_info.create ~tag_arguments "[krb5_get_init_creds_opt_*]" in
  Context_sequencer.enqueue_job_with_info ~info ~f:(fun c ->
    Raw.create
      c
      (Time_float.Span.to_sec t.tkt_lifetime |> Float.iround_nearest_exn)
      (Time_float.Span.to_sec t.renew_lifetime |> Float.iround_nearest_exn)
      t.forwardable
      t.proxiable)
  >>|? fun raw ->
  Context_sequencer.add_finalizer raw ~f:Raw.free;
  raw
;;
