open! Core
open Async
module Time = Time_unix

module Raw = struct
  type t

  external of_password
    :  Context.t
    -> ?tkt_service:string
    -> Get_init_creds_opts.Raw.t
    -> Principal.Raw.t
    -> string
    -> t Krb_result.t
    = "caml_krb5_get_init_creds_password"

  external of_keytab
    :  Context.t
    -> ?tkt_service:string
    -> Get_init_creds_opts.Raw.t
    -> Principal.Raw.t
    -> Keytab.Raw.t
    -> t Krb_result.t
    = "caml_krb5_get_init_creds_keytab"

  external free : Context.t -> t -> unit = "caml_krb5_free_cred_contents"

  external client
    :  Context.t
    -> t
    -> Principal.Raw.t Krb_result.t
    = "caml_krb5_creds_client"

  external server
    :  Context.t
    -> t
    -> Principal.Raw.t Krb_result.t
    = "caml_krb5_creds_server"

  external ticket_data
    :  Context.t
    -> t
    -> Data.t Krb_result.t
    = "caml_krb5_creds_ticket_data"

  external is_skey : t -> bool = "caml_krb5_creds_is_skey"
  external ticket_string : t -> string = "caml_krb5_creds_ticket_string"
  external second_ticket : t -> string = "caml_krb5_creds_second_ticket"
  external starttime : t -> int = "caml_krb5_creds_starttime"
  external endtime : t -> int = "caml_krb5_creds_endtime"
  external renew_until_time : t -> int = "caml_krb5_creds_renew_till"
  external forwardable : t -> bool = "caml_krb5_creds_forwardable"
  external proxiable : t -> bool = "caml_krb5_creds_proxiable"

  external keyblock
    :  Context.t
    -> t
    -> Keyblock.t Krb_result.t
    = "caml_krb5_creds_keyblock"

  external create
    :  Context.t
    -> client:Principal.Raw.t
    -> server:Principal.Raw.t
    -> ticket:string option
    -> second_ticket:string option
    -> t Krb_result.t
    = "caml_krb5_creds_create"
end

module Flags = struct
  type t =
    { forwardable : bool
    ; proxiable : bool
    }
  [@@deriving sexp_of]

  let get raw = { forwardable = Raw.forwardable raw; proxiable = Raw.proxiable raw }
end

type t =
  { raw : Raw.t
  ; starttime : Time.t
  ; endtime : Time.t
  ; renew_until : Time.t
  ; client : Principal.t
  ; server : Principal.t
  }
[@@deriving fields]

let sexp_of_t t =
  [%sexp
    { starttime = (t.starttime : Time.t Sexp_opaque_when_testing.t)
    ; endtime = (t.endtime : Time.t Sexp_opaque_when_testing.t)
    ; renew_until = (t.renew_until : Time.t Sexp_opaque_when_testing.t)
    ; client = (t.client : Principal.t)
    ; server = (t.server : Principal.t)
    }]
;;

let to_raw = raw

let krb_time_to_time krb_time =
  krb_time |> Float.of_int |> Time.Span.of_sec |> Time.of_span_since_epoch
;;

let is_skey t = Raw.is_skey t.raw
let ticket_string t = Raw.ticket_string t.raw
let second_ticket t = Raw.second_ticket t.raw
let flags t = Flags.get t.raw

let client' raw =
  let info = Krb_info.create "[krb5_creds_client]" in
  Context_sequencer.enqueue_job_with_info ~info ~f:(fun c -> Raw.client c raw)
  >>=? fun principal ->
  Context_sequencer.add_finalizer principal ~f:Principal.Raw.free;
  Principal.of_raw principal
;;

let server' raw =
  let info = Krb_info.create "[krb5_creds_server]" in
  Context_sequencer.enqueue_job_with_info ~info ~f:(fun c -> Raw.server c raw)
  >>=? fun principal ->
  Context_sequencer.add_finalizer principal ~f:Principal.Raw.free;
  Principal.of_raw principal
;;

let of_raw raw =
  client' raw
  >>=? fun client ->
  server' raw
  >>|? fun server ->
  { raw
  ; starttime = Raw.starttime raw |> krb_time_to_time
  ; endtime = Raw.endtime raw |> krb_time_to_time
  ; renew_until = Raw.renew_until_time raw |> krb_time_to_time
  ; client
  ; server
  }
;;

let of_password ?(options = Get_init_creds_opts.default) ?tkt_service principal password =
  Get_init_creds_opts.to_raw options
  >>=? fun options ->
  let tag_arguments = lazy [%message (principal : Principal.t)] in
  let info = Krb_info.create ~tag_arguments "[krb5_get_init_creds_password]" in
  Context_sequencer.enqueue_job_with_info ~info ~f:(fun c ->
    Raw.of_password c ?tkt_service options (Principal.to_raw principal) password)
  >>=? fun raw ->
  Context_sequencer.add_finalizer raw ~f:Raw.free;
  of_raw raw
;;

let of_keytab' ?(options = Get_init_creds_opts.default) ?tkt_service principal keytab =
  let open Deferred.Result.Let_syntax in
  let non_auth_failure d =
    Deferred.Result.map_error d ~f:(fun error -> `Non_auth_failure error)
  in
  let%bind options = Get_init_creds_opts.to_raw options |> non_auth_failure in
  let tag_arguments = lazy [%message (principal : Principal.t) (keytab : Keytab.t)] in
  let tag_error = function
    (* KRB5_PREAUTH_FAILED - Generic preauthentication failure *)
    | -1765328174l ->
      Deferred.return [%message "Failed to get credentials using the supplied keytab"]
    | _ -> Deferred.return Sexp.unit
  in
  let is_auth_failure = function
    (* KRB5_PREAUTH_FAILED - Generic preauthentication failure *)
    | -1765328174l
    (* KRB5_ERR_PREAUTH_FAILED - Preauthentication failed *)
    | -1765328360l -> true
    | _ -> false
  in
  let info = Krb_info.create ~tag_arguments ~tag_error "[krb5_get_init_creds_keytab]" in
  let%bind raw =
    Context_sequencer.enqueue_job_with_info' ~info ~f:(fun c ->
      Raw.of_keytab
        c
        ?tkt_service
        options
        (Principal.to_raw principal)
        (Keytab.to_raw keytab))
    |> Deferred.Result.map_error ~f:(function
      | `Raised error -> `Non_auth_failure error
      | `Krb_error (error, code) ->
        if is_auth_failure code then `Auth_failure error else `Non_auth_failure error)
  in
  Context_sequencer.add_finalizer raw ~f:Raw.free;
  of_raw raw |> non_auth_failure
;;

let of_keytab ?options ?tkt_service principal keytab =
  of_keytab' ?options ?tkt_service principal keytab
  >>| Result.map_error ~f:(function
    | `Auth_failure error -> error
    | `Non_auth_failure error -> error)
;;

let check_password principal ~password =
  Get_init_creds_opts.to_raw Get_init_creds_opts.default
  >>=? fun options ->
  let tag_arguments = lazy [%message (principal : Principal.t)] in
  let info = Krb_info.create ~tag_arguments "[krb5_get_init_creds_password]" in
  Context_sequencer.enqueue_job_with_info ~info ~f:(fun c ->
    Raw.of_password c options (Principal.to_raw principal) password
    |> Result.map ~f:(fun raw -> Raw.free c raw))
;;

let create ?ticket ?second_ticket ~client ~server () =
  let info = Krb_info.create "[krb5_creds_create]" in
  Context_sequencer.enqueue_job_with_info ~info ~f:(fun c ->
    Raw.create
      c
      ~client:(Principal.to_raw client)
      ~server:(Principal.to_raw server)
      ~ticket
      ~second_ticket)
  >>=? fun raw ->
  Context_sequencer.add_finalizer raw ~f:Raw.free;
  of_raw raw
;;

let keyblock t =
  let info = Krb_info.create "[krb5_creds_keyblock]" in
  Context_sequencer.enqueue_job_with_info ~info ~f:(fun c -> Raw.keyblock c t.raw)
  >>|? fun keyblock ->
  Context_sequencer.add_finalizer keyblock ~f:Keyblock.Raw.free;
  keyblock
;;

let ticket_data t =
  let info = Krb_info.create "[krb5_creds_ticket_data]" in
  Context_sequencer.enqueue_job_with_info ~info ~f:(fun c -> Raw.ticket_data c t.raw)
  >>|? fun ticket_data ->
  Context_sequencer.add_finalizer ticket_data ~f:Data.free;
  ticket_data
;;

let ticket t = ticket_data t >>=? fun data -> Deferred.return (Ticket.decode data)

module Expert = struct
  let of_keytab = of_keytab'
end
