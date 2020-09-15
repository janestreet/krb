open! Core
open Async

type t

module Ap_req = struct
  type t = Bigstring.Stable.V1.t [@@deriving bin_io]
end

module Ap_rep = struct
  type t = Bigstring.Stable.V1.t [@@deriving bin_io]
end

module Krb_cred = struct
  type t = Bigstring.Stable.V1.t [@@deriving bin_io]
end

module Raw = struct
  external init : Context.t -> t Krb_result.t = "caml_krb5_auth_con_init"
  external free : Context.t -> t -> unit = "caml_krb5_auth_con_free"

  external setuseruserkey
    :  Context.t
    -> t
    -> Keyblock.t
    -> unit Krb_result.t
    = "caml_krb5_auth_con_setuseruserkey"

  external setflags
    :  Context.t
    -> t
    -> Krb_flags.Auth_context.t list
    -> unit
    = "caml_krb5_auth_con_setflags"

  external setaddrs_compat
    :  Context.t
    -> t
    -> local_port:int
    -> remote_port:int
    -> unit Krb_result.t
    = "caml_krb5_auth_con_setaddrs_compat"

  external setaddrs
    :  Context.t
    -> t
    -> local_port:int
    -> remote_port:int
    -> local_addr:int32
    -> remote_addr:int32
    -> unit Krb_result.t
    = "caml_krb5_auth_con_setaddrs_bytecode" "caml_krb5_auth_con_setaddrs"

  external make_priv
    :  Context.t
    -> t
    -> Bigsubstring.t
    -> Bigstring.t Krb_result.t
    = "caml_krb5_mk_priv"

  external read_priv
    :  Context.t
    -> t
    -> Bigsubstring.t
    -> Bigstring.t Krb_result.t
    = "caml_krb5_rd_priv"

  external make_safe
    :  Context.t
    -> t
    -> Bigsubstring.t
    -> Bigstring.t Krb_result.t
    = "caml_krb5_mk_safe"

  external read_safe
    :  Context.t
    -> t
    -> Bigsubstring.t
    -> Bigstring.t Krb_result.t
    = "caml_krb5_rd_safe"

  external make_ap_req
    :  Context.t
    -> t
    -> Krb_flags.Ap_req.t list
    -> service:string
    -> hostname:string
    -> Cred_cache.Raw.t
    -> Bigstring.t Krb_result.t
    = "caml_krb5_mk_req_bytecode" "caml_krb5_mk_req_native"

  external make_ap_req_extended
    :  Context.t
    -> t
    -> Krb_flags.Ap_req.t list
    -> Credentials.Raw.t
    -> Bigstring.t Krb_result.t
    = "caml_krb5_mk_req_extended"

  external read_ap_req_client
    :  Context.t
    -> t
    -> ap_req:Ap_req.t
    -> Principal.Raw.t
    -> Keytab.Raw.t option
    -> Principal.Raw.t Krb_result.t
    = "caml_krb5_rd_req"

  external make_ap_rep : Context.t -> t -> Ap_rep.t Krb_result.t = "caml_krb5_mk_rep"

  external read_ap_rep
    :  Context.t
    -> t
    -> Ap_rep.t
    -> unit Krb_result.t
    = "caml_krb5_rd_rep"

  external make_krb_cred
    :  Context.t
    -> t
    -> client:Principal.Raw.t
    -> Cred_cache.Raw.t
    -> forwardable:bool
    -> Krb_cred.t Krb_result.t
    = "caml_krb5_fwd_tgt_cred"

  external cc_store_krb_cred
    :  Context.t
    -> t
    -> Cred_cache.Raw.t
    -> Krb_cred.t
    -> unit Krb_result.t
    = "caml_krb5_cc_store_krb_cred"
end

type 'a with_inets =
  local_inet:Socket.Address.Inet.t -> remote_inet:Socket.Address.Inet.t -> 'a

let create () =
  let info = Krb_info.create "[krb5_auth_con_init]" in
  Context_sequencer.enqueue_job_with_info ~info ~f:Raw.init
  >>|? fun t ->
  Context_sequencer.add_finalizer t ~f:Raw.free;
  t
;;

let set_flags raw_auth flags =
  Context_sequencer.enqueue_job_exn ~f:(fun c -> Raw.setflags c raw_auth flags)
;;

let set_addrs_compat raw_auth ~local_port ~remote_port =
  let tag_arguments = lazy [%message (local_port : int) (remote_port : int)] in
  let info = Krb_info.create ~tag_arguments "[krb5_auth_con_setaddrs_compat]" in
  Context_sequencer.enqueue_job_with_info ~info ~f:(fun c ->
    Raw.setaddrs_compat c raw_auth ~local_port ~remote_port)
;;

let set_addrs raw_auth ~local_port ~remote_port ~local_addr ~remote_addr =
  let tag_arguments =
    lazy
      [%message
        (local_port : int)
          (remote_port : int)
          (local_addr : Unix.Inet_addr.t)
          (remote_addr : Unix.Inet_addr.t)]
  in
  let info = Krb_info.create ~tag_arguments "[krb5_auth_con_setaddrs]" in
  Context_sequencer.enqueue_job_with_info ~info ~f:(fun c ->
    Raw.setaddrs
      c
      raw_auth
      ~local_port
      ~remote_port
      ~local_addr:(Unix.Inet_addr.inet4_addr_to_int32_exn local_addr)
      ~remote_addr:(Unix.Inet_addr.inet4_addr_to_int32_exn remote_addr))
;;

let set_user_to_user_key raw_auth keyblock =
  let info = Krb_info.create "[krb5_auth_con_setuseruserkey]" in
  Context_sequencer.enqueue_job_with_info ~info ~f:(fun c ->
    Raw.setuseruserkey c raw_auth keyblock)
;;

let common_init ?user_to_user_key ?handle_addrs () =
  create ()
  >>=? fun t ->
  set_flags t [ KRB5_AUTH_CONTEXT_DO_SEQUENCE ]
  >>= fun () ->
  Option.value_map handle_addrs ~default:Deferred.Or_error.ok_unit ~f:(fun f -> f t)
  >>=? fun () ->
  (match user_to_user_key with
   | None -> Deferred.Or_error.ok_unit
   | Some keyblock -> set_user_to_user_key t keyblock)
  >>|? fun () -> t
;;

let handle_inet_addrs_compat ~local_inet ~remote_inet t =
  let `Inet (_, local_port), `Inet (_, remote_port) = local_inet, remote_inet in
  set_addrs_compat t ~local_port ~remote_port
;;

let handle_inet_addrs ~local_inet ~remote_inet t =
  let `Inet (local_addr, local_port), `Inet (remote_addr, remote_port) =
    local_inet, remote_inet
  in
  set_addrs t ~local_port ~remote_port ~local_addr ~remote_addr
;;

module Client_common = struct
  let mk_req_extended auth_context ?(flags = []) credentials =
    let tag_arguments = lazy [%message (credentials : Credentials.t)] in
    let info = Krb_info.create ~tag_arguments "[krb5_mk_req_extended]" in
    Context_sequencer.enqueue_job_with_info ~info ~f:(fun c ->
      Raw.make_ap_req_extended c auth_context flags (Credentials.to_raw credentials))
  ;;

  let init ?handle_addrs flags credentials =
    common_init ?handle_addrs ()
    >>=? fun auth_context ->
    mk_req_extended auth_context ~flags credentials
    >>|? fun ap_req -> auth_context, ap_req
  ;;
end

module Service_common = struct
  let read_ap_req_client auth_context ap_req principal keytab =
    let tag_arguments =
      lazy [%message (principal : Principal.t) (keytab : Keytab.t option)]
    in
    let info = Krb_info.create ~tag_arguments "[krb5_rd_req]" in
    Context_sequencer.enqueue_job_with_info ~info ~f:(fun c ->
      Raw.read_ap_req_client
        c
        auth_context
        ~ap_req
        (Principal.to_raw principal)
        (Option.map keytab ~f:Keytab.to_raw))
    >>=? fun raw_principal ->
    Context_sequencer.add_finalizer raw_principal ~f:Principal.Raw.free;
    Principal.of_raw raw_principal
  ;;

  let init ?handle_addrs principal authentication_key ~ap_req =
    let keytab, user_to_user_key =
      match authentication_key with
      | `Keytab keytab -> Some keytab, None
      | `User_to_user keyblock -> None, Some keyblock
    in
    common_init ?handle_addrs ?user_to_user_key ()
    >>=? fun auth_context ->
    read_ap_req_client auth_context ap_req principal keytab
    >>|? fun client -> auth_context, client
  ;;
end

module V0 = struct
  module Client = struct
    type 'a with_init_args =
      Cred_cache.t -> Krb_flags.Ap_req.t list -> service:string -> hostname:string -> 'a

    let mk_req auth_context ccache ?(flags = []) ~service ~hostname =
      let tag_arguments =
        lazy [%message (ccache : Cred_cache.t) (service : string) (hostname : string)]
      in
      let info = Krb_info.create ~tag_arguments "[krb5_mk_req]" in
      Context_sequencer.enqueue_job_with_info ~info ~f:(fun c ->
        Raw.make_ap_req
          c
          auth_context
          flags
          ~service
          ~hostname
          (Cred_cache.to_raw ccache))
    ;;

    let init_aux ?handle_addrs ccache flags ~service ~hostname =
      common_init ?handle_addrs ()
      >>=? fun auth_context ->
      mk_req auth_context ccache ~flags ~service ~hostname
      >>|? fun ap_req -> auth_context, ap_req
    ;;

    let init ccache flags ~service ~hostname ~local_inet ~remote_inet =
      let handle_addrs = handle_inet_addrs_compat ~local_inet ~remote_inet in
      init_aux ~handle_addrs ccache flags ~service ~hostname
    ;;

    let init_without_addrs ccache flags ~service ~hostname =
      init_aux ccache flags ~service ~hostname
      >>|? fun (auth_context, ap_req) ->
      ignore (auth_context : t);
      ap_req
    ;;
  end

  module Service = struct
    type 'a with_init_args =
      Principal.t
      -> [ `Keytab of Keytab.t | `User_to_user of Keyblock.t ]
      -> ap_req:Ap_req.t
      -> 'a

    let init principal authentication_key ~ap_req ~local_inet ~remote_inet =
      let handle_addrs = handle_inet_addrs_compat ~local_inet ~remote_inet in
      Service_common.init ~handle_addrs principal authentication_key ~ap_req
    ;;
  end
end

(* V1 uses [mk_req_extended], so it takes in credentials rather than a service name, host
   name, and credential cache.*)
module V1 = struct
  module Client = struct
    type 'a with_init_args = Krb_flags.Ap_req.t list -> Credentials.t -> 'a

    let init flags credentials ~local_inet ~remote_inet =
      let handle_addrs = handle_inet_addrs_compat ~local_inet ~remote_inet in
      Client_common.init ~handle_addrs flags credentials
    ;;
  end

  module Service = V0.Service
end

(* V0 and V1 used a broken [set_addrs] function (it didn't correctly
   set the addresses). It doesn't actually matter that it is wrong, because the only check
   is for consistency across what the server and client set. In V2, we start to use
   [set_addrs] correctly, to be compatible with krb [genaddrs]. *)
module Client = struct
  type 'a with_init_args = 'a V1.Client.with_init_args

  let init flags credentials ~local_inet ~remote_inet =
    let handle_addrs t = handle_inet_addrs t ~local_inet ~remote_inet in
    Client_common.init ~handle_addrs flags credentials
  ;;

  let init_without_addrs flags credentials =
    Client_common.init flags credentials
    >>|? fun (auth_context, ap_req) ->
    ignore (auth_context : t);
    ap_req
  ;;

  let read_and_verify_ap_rep auth_context ~ap_rep =
    let info = Krb_info.create "[krb5_rd_rep]" in
    Context_sequencer.enqueue_job_with_info ~info ~f:(fun c ->
      Raw.read_ap_rep c auth_context ap_rep)
  ;;

  let make_krb_cred t ~forwardable ~client ccache =
    let tag_arguments = lazy [%message (client : Principal.t) (ccache : Cred_cache.t)] in
    let tag_error = function
      (* KRB5KDC_ERR_BADOPTION - KDC can't fulfill requested option *)
      | -1765328371l -> return [%message "Make sure your tgt is forwardable."]
      | _ -> return Sexp.unit
    in
    let info = Krb_info.create ~tag_arguments ~tag_error "[krb5_fwd_tgt_creds]" in
    Context_sequencer.enqueue_job_with_info ~info ~f:(fun ctx ->
      let client = Principal.to_raw client in
      let ccache = Cred_cache.to_raw ccache in
      Raw.make_krb_cred ctx t ~client ccache ~forwardable)
  ;;
end

module Service = struct
  type 'a with_init_args = 'a V1.Service.with_init_args

  let init principal authentication_key ~ap_req ~local_inet ~remote_inet =
    let handle_addrs t = handle_inet_addrs t ~local_inet ~remote_inet in
    Service_common.init ~handle_addrs principal authentication_key ~ap_req
  ;;

  let init_without_addrs principal authentication_key ~ap_req =
    Service_common.init principal authentication_key ~ap_req
    >>|? fun (auth_context, client_principal) ->
    ignore (auth_context : t);
    client_principal
  ;;

  let make_ap_rep auth_context =
    let info = Krb_info.create "[krb5_mk_rep]" in
    Context_sequencer.enqueue_job_with_info ~info ~f:(fun c ->
      Raw.make_ap_rep c auth_context)
  ;;

  let read_krb_cred_into_cred_cache auth_context krb_cred ccache =
    let tag_arguments = lazy [%message (ccache : Cred_cache.t)] in
    let info = Krb_info.create ~tag_arguments "[krb5_cc_store_krb_cred]" in
    Context_sequencer.enqueue_job_with_info ~info ~f:(fun ctx ->
      let ccache = Cred_cache.to_raw ccache in
      Raw.cc_store_krb_cred ctx auth_context ccache krb_cred)
  ;;
end

module Safe = struct
  let encode auth_context data =
    let info = Krb_info.create "[krb5_mk_safe]" in
    Context_sequencer.enqueue_blocking_if_below_encryption_size_threshold
      ~data_size:(Bigsubstring.length data)
      ~info
      ~f:(fun c -> Raw.make_safe c auth_context data)
  ;;

  let decode auth_context data =
    let info = Krb_info.create "[krb5_rd_safe]" in
    Context_sequencer.enqueue_blocking_if_below_encryption_size_threshold
      ~data_size:(Bigsubstring.length data)
      ~info
      ~f:(fun c -> Raw.read_safe c auth_context data)
  ;;
end

module Priv = struct
  let encode auth_context data =
    let info = Krb_info.create "[krb5_mk_priv]" in
    Context_sequencer.enqueue_blocking_if_below_encryption_size_threshold
      ~data_size:(Bigsubstring.length data)
      ~info
      ~f:(fun c -> Raw.make_priv c auth_context data)
  ;;

  let decode auth_context data =
    let info = Krb_info.create "[krb5_rd_priv]" in
    Context_sequencer.enqueue_blocking_if_below_encryption_size_threshold
      ~data_size:(Bigsubstring.length data)
      ~info
      ~f:(fun c -> Raw.read_priv c auth_context data)
  ;;
end
