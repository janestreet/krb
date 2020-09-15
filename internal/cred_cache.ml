open! Core
open Async

module Raw = struct
  type t
  type cred_cache = t

  module Cursor = struct
    type t

    external create
      :  Context.t
      -> cred_cache
      -> t Krb_result.t
      = "caml_krb5_cc_start_seq_get"

    external advance
      :  Context.t
      -> cred_cache
      -> t
      -> Credentials.Raw.t option Krb_result.t
      = "caml_krb5_cc_next_cred"

    external free
      :  Context.t
      -> cred_cache
      -> t
      -> unit Krb_result.t
      = "caml_krb5_cc_end_seq_get"
  end

  external initialize
    :  Context.t
    -> t
    -> Principal.Raw.t
    -> unit Krb_result.t
    = "caml_krb5_cc_initialize"

  external default : Context.t -> t Krb_result.t = "caml_krb5_cc_default"

  external principal
    :  Context.t
    -> t
    -> Principal.Raw.t Krb_result.t
    = "caml_krb5_cc_get_principal"

  external free : Context.t -> t -> unit = "caml_krb5_cc_close"

  external cache_match
    :  Context.t
    -> Principal.Raw.t
    -> t Krb_result.t
    = "caml_krb5_cc_cache_match"

  external new_unique : Context.t -> string -> t Krb_result.t = "caml_krb5_cc_new_unique"

  external full_name
    :  Context.t
    -> t
    -> string Krb_result.t
    = "caml_krb5_cc_get_full_name"

  external get_type : Context.t -> t -> string = "caml_krb5_cc_get_type"

  external store_cred
    :  Context.t
    -> t
    -> Credentials.Raw.t
    -> unit Krb_result.t
    = "caml_krb5_cc_store_cred"

  external resolve : Context.t -> string -> t Krb_result.t = "caml_krb5_cc_resolve"

  external get_credentials
    :  Context.t
    -> Krb_flags.Get_credentials.t list
    -> t
    -> request:Credentials.Raw.t
    -> Credentials.Raw.t Krb_result.t
    = "caml_krb5_get_credentials"

  external get_renewed_creds
    :  Context.t
    -> Principal.Raw.t
    -> t
    -> tkt_service:string
    -> Credentials.Raw.t Krb_result.t
    = "caml_krb5_get_renewed_creds"
end

module Full_name = struct
  type t = string

  let sexp_of_t str =
    let str =
      if am_running_inline_test
      then String.take_while str ~f:(fun x -> not (Char.equal x ':'))
      else str
    in
    [%sexp_of: string] str
  ;;
end

type t =
  { raw : Raw.t
  ; full_name : Full_name.t
  }
[@@deriving fields]

let sexp_of_t t = [%sexp { full_name = (t.full_name : Full_name.t) }]
let compare t1 t2 = String.compare t1.full_name t2.full_name
let hash t = String.hash t.full_name
let hash_fold_t state t = Hash.fold_string state t.full_name
let to_raw = raw

let of_raw raw =
  let tag_result full_name = [%message (full_name : Full_name.t)] in
  let info = Krb_info.create ~tag_result "[krb5_cc_get_full_name]" in
  Context_sequencer.enqueue_job_with_info ~info ~f:(fun c -> Raw.full_name c raw)
  >>|? fun full_name -> { raw; full_name }
;;

module Cred_cache_cursor = Cursor.Make (struct
    module Container = struct
      type raw = Raw.t
      type nonrec t = t [@@deriving sexp_of]

      let tag t = [%message "" ~cred_cache:(t : t)]
      let to_raw = to_raw
    end

    module Item = struct
      type raw = Credentials.Raw.t
      type t = Credentials.t

      let of_raw = Credentials.of_raw
      let free = Credentials.Raw.free
    end

    module Cursor = struct
      type t = Raw.Cursor.t

      let start = Raw.Cursor.create
      let advance = Raw.Cursor.advance
      let finish = Raw.Cursor.free
    end

    let info = "[krb5_cc_start_seq_get]//[krb5_cc_next_cred]//[krb5_cc_end_seq_get]"
  end)

let default () =
  let info = Krb_info.create "[krb5_cc_default]" in
  Context_sequencer.enqueue_job_with_info ~info ~f:Raw.default
  >>=? fun ccache ->
  Context_sequencer.add_finalizer ccache ~f:Raw.free;
  of_raw ccache
;;

let initialize t principal =
  let tag_arguments = lazy [%message (principal : Principal.t) ~cred_cache:(t : t)] in
  let info = Krb_info.create ~tag_arguments "[krb5_cc_initialize]" in
  Context_sequencer.enqueue_job_with_info ~info ~f:(fun c ->
    Raw.initialize c t.raw (Principal.to_raw principal))
;;

let new_unique cc_type =
  let tag_arguments = lazy [%message (cc_type : Cache_type.t)] in
  let info = Krb_info.create ~tag_arguments "[krb5_cc_new_unique]" in
  Context_sequencer.enqueue_job_with_info ~info ~f:(fun c ->
    Raw.new_unique c (Cache_type.to_string cc_type))
  >>=? fun raw ->
  Context_sequencer.add_finalizer raw ~f:Raw.free;
  of_raw raw
;;

let create cc_type principal =
  let open Deferred.Or_error.Let_syntax in
  let%bind t = new_unique cc_type in
  let%bind () = initialize t principal in
  return t
;;

let cache_type t =
  Context_sequencer.enqueue_job_exn ~f:(fun c -> Raw.get_type c t.raw)
  >>| fun type_string -> Cache_type.of_string type_string
;;

let store t cred =
  let tag_arguments = lazy [%message "" ~cred_cache:(t : t) (cred : Credentials.t)] in
  let info = Krb_info.create ~tag_arguments "[krb5_cc_store_cred]" in
  Context_sequencer.enqueue_job_with_info ~info ~f:(fun c ->
    Raw.store_cred c t.raw (Credentials.to_raw cred))
;;

let result_list_iter xs ~f = List.fold_result ~init:() xs ~f:(fun () x -> f x)

let initialize_and_store t principal creds =
  let tag_arguments =
    lazy
      [%message
        (principal : Principal.t) ~cred_cache:(t : t) (creds : Credentials.t list)]
  in
  let info = Krb_info.create ~tag_arguments "[krb5_cc_initialize]/[krb5_cc_store_cred]" in
  Context_sequencer.enqueue_job_with_info ~info ~f:(fun c ->
    let open Result.Let_syntax in
    let%bind () = Raw.initialize c t.raw (Principal.to_raw principal) in
    result_list_iter creds ~f:(fun cred ->
      Raw.store_cred c t.raw (Credentials.to_raw cred)))
;;

let principal t =
  let tag_arguments = lazy [%message "" ~cred_cache:(t : t)] in
  let tag_error = function
    (* KRB5_FCC_NOFILE - No credentials cache file found *)
    | -1765328189l ->
      (match%map cache_type t with
       | MEMORY ->
         [%message "call [Cred_cache.initialize_with_creds] to create a credential cache."]
       | FILE | DIR -> [%message "call `kinit` to create a credential cache."]
       | _ -> Sexp.unit)
    | _ -> return Sexp.unit
  in
  let info = Krb_info.create ~tag_arguments ~tag_error "[krb5_cc_get_principal]" in
  Context_sequencer.enqueue_job_with_info ~info ~f:(fun c -> Raw.principal c t.raw)
  >>=? fun principal ->
  Context_sequencer.add_finalizer principal ~f:Principal.Raw.free;
  Principal.of_raw principal
;;

let creds t =
  Cred_cache_cursor.get_all t
  >>=? fun creds ->
  Context_sequencer.enqueue_job_exn ~f:(fun c ->
    List.filter creds ~f:(fun credentials ->
      let principal = Credentials.server credentials in
      not (Principal.Raw.is_config_principal c (Principal.to_raw principal))))
  |> Deferred.ok
;;

let get_credentials
      ?(tag_error_with_all_credentials = Config.verbose_errors)
      ?(ensure_cached_valid_for_at_least = Time.Span.of_min 10.)
      ~flags
      t
      ~request
  =
  let tag_arguments = lazy [%message "" ~cred_cache:(t : t) (request : Credentials.t)] in
  let creds_sexp () =
    match%map creds t with
    | Ok creds -> [%sexp_of: Credentials.t list] creds
    | Error e -> [%sexp_of: Error.t] e
  in
  let make_error info =
    if tag_error_with_all_credentials
    then (
      let%bind credentials = creds_sexp () in
      return [%message info (credentials : Sexp.t)])
    else return [%message info]
  in
  let tag_error code =
    match code with
    (* KRB5_CC_NOTFOUND - Matching credential not found *)
    | -1765328243l ->
      make_error
        "Run `klist` to make sure you have the proper credentials. You may need to call \
         `kinit` to get fresh credentials."
    (* KRB5KRB_AP_ERR_TKT_EXPIRED - Ticket expired *)
    | -1765328352l ->
      make_error
        "Run `jskrenew status` to ensure ticket renewal is working properly. You may \
         need to call `kinit` to get fresh credentials."
    | _ -> return Sexp.unit
  in
  let info = Krb_info.create ~tag_arguments ~tag_error "[krb5_get_credentials]" in
  Context_sequencer.enqueue_job_with_info ~info ~f:(fun c ->
    Raw.get_credentials c flags t.raw ~request:(Credentials.to_raw request))
  >>=? fun credentials_raw ->
  Context_sequencer.add_finalizer credentials_raw ~f:Credentials.Raw.free;
  Credentials.of_raw credentials_raw
  >>=? fun credentials ->
  let has_cached_flag =
    List.mem flags ~equal:Krb_flags.Get_credentials.equal KRB5_GC_CACHED
  in
  let end_time_is_soon =
    Time.(
      add (now ()) ensure_cached_valid_for_at_least >= Credentials.endtime credentials)
  in
  if has_cached_flag && end_time_is_soon
  then (
    let%bind error = make_error "Cached ticket does not have enough remaining lifetime" in
    Deferred.Or_error.error_s
      [%message
        ""
          ~should_be_valid_for_at_least:(ensure_cached_valid_for_at_least : Time.Span.t)
          ~_:(force tag_arguments : Sexp.t)
          ~_:(error : Sexp.t)])
  else Deferred.Or_error.return credentials
;;

let get_cached_tgt ?ensure_valid_for_at_least t =
  principal t
  >>=? fun principal ->
  let realm = Principal.realm principal in
  Principal.of_string (sprintf "krbtgt/%s@%s" realm realm)
  >>=? fun tgt_principal ->
  Credentials.create ~client:principal ~server:tgt_principal ()
  >>=? fun request ->
  get_credentials
    ?ensure_cached_valid_for_at_least:ensure_valid_for_at_least
    ~flags:[ KRB5_GC_CACHED ]
    t
    ~request
;;

let renew t cred =
  let client = Principal.to_raw (Credentials.client cred) in
  let server = Principal.to_string (Credentials.server cred) in
  let info = Krb_info.create "[krb5_get_renewed_creds]" in
  Context_sequencer.enqueue_job_with_info ~info ~f:(fun c ->
    Raw.get_renewed_creds c client t.raw ~tkt_service:server)
  >>=? fun renewed_cred_raw ->
  Context_sequencer.add_finalizer renewed_cred_raw ~f:Credentials.Raw.free;
  Credentials.of_raw renewed_cred_raw
;;

module Expert = struct
  let new_unique = new_unique
  let cache_type = cache_type
  let creds = creds

  let cache_match client =
    let info = Krb_info.create "[krb5_cc_cache_match]" in
    Context_sequencer.enqueue_job_with_info ~info ~f:(fun c ->
      Raw.cache_match c (Principal.to_raw client))
    >>=? fun ccache ->
    Context_sequencer.add_finalizer ccache ~f:Raw.free;
    of_raw ccache
  ;;

  let resolve path =
    let info = Krb_info.create "[krb5_cc_resolve]" in
    Context_sequencer.enqueue_job_with_info ~info ~f:(fun c -> Raw.resolve c path)
    >>=? fun ccache ->
    Context_sequencer.add_finalizer ccache ~f:Raw.free;
    of_raw ccache
  ;;

  let full_name = full_name
end
