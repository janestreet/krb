open! Core

module Raw = struct
  type t

  external kvno : t -> int = "caml_krb5_ticket_kvno"
  external free : Context.t -> t -> unit = "caml_krb5_free_ticket"
  external decode : Data.t -> t Krb_result.t = "caml_krb5_decode_ticket"
  external enctype : t -> int = "caml_krb5_ticket_enctype"
end

type t = Raw.t

let kvno t = Raw.kvno t
let enctype t = Or_error.try_with (fun () -> Enctype.of_int (Raw.enctype t))

let decode data =
  let open Or_error.Let_syntax in
  let info = "[krb5_decode_ticket]" in
  let%bind ticket = Raw.decode data |> Krb_result.to_or_error ~info in
  Context_sequencer.add_finalizer ticket ~f:Raw.free;
  return ticket
;;
