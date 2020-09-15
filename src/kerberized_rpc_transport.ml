open! Core
open Async
open Import
module Transport = Async_rpc_kernel.Rpc.Transport

let message_size_ok ~max_message_size ~payload_length =
  payload_length >= 0 && payload_length <= max_message_size
;;

module Reader = struct
  type t =
    { reader : Reader.t
    ; decode : Bigsubstring.t -> Bigstring.t Deferred.Or_error.t
    ; max_message_size : int
    }
  [@@deriving fields, sexp_of]

  let with_reader f t = f t.reader
  let close = with_reader Reader.close
  let is_closed = with_reader Reader.is_closed

  let check_message_size t ~payload_length =
    if not (message_size_ok ~max_message_size:t.max_message_size ~payload_length)
    then
      Error.raise_s
        [%message
          "Kerberized_rpc_transport: message too small or too big"
            ~message_size:(payload_length : int)
            (t.max_message_size : int)]
  ;;

  let all_unit_then_return l ret_val =
    match l with
    | [] -> return ret_val (* avoid deferred operations in the common case *)
    | _ -> Deferred.all_unit l >>| fun () -> ret_val
  ;;

  let read_forever t ~on_message ~on_end_of_batch =
    let finish_loop ~consumed ~need ~wait_before_reading =
      on_end_of_batch ();
      all_unit_then_return wait_before_reading (`Consumed (consumed, `Need need))
    in
    let rec loop buf ~pos ~len ~consumed ~wait_before_reading =
      if len < Transport.Header.length
      then finish_loop ~consumed ~need:Transport.Header.length ~wait_before_reading
      else (
        let payload_len = Transport.Header.unsafe_get_payload_length buf ~pos in
        let total_len = Transport.Header.length + payload_len in
        if len < total_len
        then finish_loop ~consumed ~need:total_len ~wait_before_reading
        else (
          let consumed = consumed + total_len in
          let%bind (result : _ Transport.Handler_result.t) =
            let%map payload =
              Bigsubstring.create
                buf
                ~pos:(pos + Transport.Header.length)
                ~len:payload_len
              |> t.decode
            in
            let payload = ok_exn payload in
            let payload_length = Bigstring.length payload in
            check_message_size t ~payload_length;
            on_message payload ~pos:0 ~len:payload_length
          in
          match result with
          | Stop x ->
            all_unit_then_return wait_before_reading (`Stop_consumed (x, consumed))
          | Continue ->
            loop
              buf
              ~pos:(pos + total_len)
              ~len:(len - total_len)
              ~consumed
              ~wait_before_reading
          | Wait d ->
            let wait_before_reading =
              if Deferred.is_determined d
              then wait_before_reading
              else d :: wait_before_reading
            in
            loop
              buf
              ~pos:(pos + total_len)
              ~len:(len - total_len)
              ~consumed
              ~wait_before_reading))
    in
    let handle_chunk buf ~pos ~len =
      loop buf ~pos ~len ~consumed:0 ~wait_before_reading:[]
    in
    Reader.read_one_chunk_at_a_time t.reader ~handle_chunk
    >>| function
    | `Eof | `Eof_with_unconsumed_data _ -> Error `Eof
    | `Stopped x -> Ok x
  ;;
end

(* We must be careful that when [Writer.send_bin_prot] returns, these bytes are properly
   flushed upon a subsequent [Writer.close]. [Async_rpc.Rpc_transport] satisfies this
   property by sending the bytes to the underlying [Writer.t] in the same async job.
   This transport doesn't have that luxury because we want to encrypt in a separate
   thread. The following client code demonstrates this problem:

   {[
     Krb.Rpc.Connection.with_client
       ~krb_mode
       where_to_connect
       (fun connection ->
          Rpc.One_way.dispatch_exn one_way_rpc connection arg;
          return ())
   ]} *)
module Pending_writes : sig
  module Id : T

  type t [@@deriving sexp_of]

  val create : unit -> t

  (** The returned [Deferred.t] is determined when all the current pending writes have
      been marked as scheduled. *)
  val all_scheduled : t -> unit Deferred.t

  val add : t -> Id.t
  val mark_scheduled : t -> Id.t -> unit
end = struct
  module Id = Unique_id.Int ()

  type t = unit Ivar.t Id.Table.t

  let sexp_of_t t = Int.sexp_of_t (Hashtbl.length t)
  let create () = Id.Table.create ()

  let all_scheduled t =
    Hashtbl.to_alist t
    |> List.map ~f:(fun (_, ivar) -> Ivar.read ivar)
    |> Deferred.List.all_unit
  ;;

  let add t =
    let id = Id.create () in
    Hashtbl.add_exn t ~key:id ~data:(Ivar.create ());
    id
  ;;

  let mark_scheduled t id =
    match Hashtbl.find_and_remove t id with
    | None -> ()
    | Some ivar -> Ivar.fill ivar ()
  ;;
end

module Writer = struct
  type t =
    { writer : Writer.t
    ; encode : Bigsubstring.t -> Bigstring.t Deferred.Or_error.t
    ; max_message_size : int
    ; close_started : unit Ivar.t
    ; pending_writes : Pending_writes.t
    ; on_done_with_internal_buffer : Bigstring.t -> unit
    }
  [@@deriving fields, sexp_of]

  let zero_buffer buffer =
    Bigstring.memset buffer ~pos:0 ~len:(Bigstring.length buffer) '\000'
  ;;

  let create ~writer ~encode ~max_message_size ~on_done_with_internal_buffer =
    let close_started = Ivar.create () in
    let pending_writes = Pending_writes.create () in
    let on_done_with_internal_buffer =
      match on_done_with_internal_buffer with
      | `Do_nothing -> (ignore : Bigstring.t -> unit)
      | `Zero -> zero_buffer
    in
    (* As per [Async_rpc.Rpc_transport] *)
    Writer.set_raise_when_consumer_leaves writer false;
    Fields.create
      ~writer
      ~encode
      ~max_message_size
      ~close_started
      ~pending_writes
      ~on_done_with_internal_buffer
  ;;

  let monitor t = Writer.monitor t.writer

  (* [bytes_to_write] might not be exactly correct because it doesn't take pending writes
     into account *)
  let bytes_to_write t = Writer.bytes_to_write t.writer
  let is_closed t = Ivar.is_full t.close_started || Writer.is_closed t.writer

  let close t =
    if not (is_closed t)
    then (
      Ivar.fill t.close_started ();
      let%bind () = Pending_writes.all_scheduled t.pending_writes in
      Writer.close t.writer)
    else Writer.close_finished t.writer
  ;;

  let flushed t =
    let%bind () = Pending_writes.all_scheduled t.pending_writes in
    Writer.flushed t.writer
  ;;

  let ready_to_write = flushed

  (* Similar to [Async_rpc.Rpc_transport] *)
  let stopped t =
    Deferred.any
      [ Ivar.read t.close_started
      ; Writer.close_started t.writer
      ; Writer.consumer_left t.writer
      ]
  ;;

  let message_size_ok t = message_size_ok ~max_message_size:t.max_message_size

  let bin_write_payload_length buf ~pos x =
    Transport.Header.unsafe_set_payload_length buf ~pos x;
    pos + Transport.Header.length
  ;;

  let send_payload t payload =
    let id = Pending_writes.add t.pending_writes in
    Scheduler.within' ~monitor:(monitor t) (fun () ->
      let%map encoded_payload = t.encode (Bigsubstring.create payload) in
      t.on_done_with_internal_buffer payload;
      let encoded_payload = ok_exn encoded_payload in
      if Writer.can_write t.writer
      then (
        let payload_length = Bigstring.length encoded_payload in
        Writer.write_bin_prot_no_size_header
          t.writer
          ~size:Transport.Header.length
          bin_write_payload_length
          payload_length;
        Writer.schedule_bigstring t.writer encoded_payload);
      Pending_writes.mark_scheduled t.pending_writes id)
  ;;

  let send_bin_prot (type a) t (bin_writer : a Bin_prot.Type_class.writer) (value : a) =
    if is_closed t
    then Transport.Send_result.Closed
    else (
      let size = bin_writer.size value in
      let payload = Bigstring.create size in
      let bytes_written = bin_writer.write payload ~pos:0 value in
      assert (Int.equal bytes_written size);
      if message_size_ok t ~payload_length:size
      then (
        don't_wait_for (send_payload t payload);
        Transport.Send_result.Sent ())
      else Message_too_big { size; max_message_size = t.max_message_size })
  ;;

  (* We always need to copy the inputs to be able to pass them to [encode]. *)
  let send_bin_prot_and_bigstring_non_copying
        (type a)
        t
        (bin_writer : a Bin_prot.Type_class.writer)
        (value : a)
        ~buf
        ~pos
        ~len
    =
    if is_closed t
    then Transport.Send_result.Closed
    else (
      let bin_prot_size = bin_writer.size value in
      let payload_size = bin_prot_size + len in
      let payload = Bigstring.create payload_size in
      let bin_prot_bytes_written = bin_writer.write payload ~pos:0 value in
      assert (Int.equal bin_prot_size bin_prot_bytes_written);
      Bigstring.blit
        ~src:buf
        ~src_pos:pos
        ~dst:payload
        ~dst_pos:bin_prot_bytes_written
        ~len;
      if message_size_ok t ~payload_length:payload_size
      then send_payload t payload |> Transport.Send_result.Sent
      else Message_too_big { size = payload_size; max_message_size = t.max_message_size })
  ;;

  let send_bin_prot_and_bigstring t bin_writer_t value ~buf ~pos ~len =
    match send_bin_prot_and_bigstring_non_copying t bin_writer_t value ~buf ~pos ~len with
    | Transport.Send_result.Sent def ->
      don't_wait_for def;
      Transport.Send_result.Sent ()
    | Closed -> Closed
    | Message_too_big mtb -> Message_too_big mtb
  ;;
end

(* copied from RPC (which in turn is copied from reader0.ml) *)
let default_max_message_size = 100 * 1024 * 1024

let of_connection
      ?(on_done_with_internal_buffer = `Do_nothing)
      ?(max_message_size = default_max_message_size)
      connection
  =
  if max_message_size < 0
  then
    failwithf
      "[Kerberized_rpc_transport.of_connection] got negative max message size: %d"
      max_message_size
      ();
  match Protocol.Connection.protocol_version connection with
  | `Test_mode | `Versioned 2 | `Versioned 3 | `Versioned 4 ->
    let transport =
      match Protocol.Connection.auth_context connection with
      | `Test_mode ->
        (* Pretend that the connection type is [Auth] so there's no encoding or decoding. *)
        let reader = Protocol.Connection.reader connection in
        let writer = Protocol.Connection.writer connection in
        Rpc.Transport.of_reader_writer ~max_message_size reader writer
      | `Prod auth_context ->
        let (conn_type : Conn_type.t) = Protocol.Connection.conn_type connection in
        let reader = Protocol.Connection.reader connection in
        let writer = Protocol.Connection.writer connection in
        let encode_decode =
          match conn_type with
          | Auth -> None
          | Safe ->
            Some Internal.Auth_context.Safe.(encode auth_context, decode auth_context)
          | Priv ->
            Some Internal.Auth_context.Priv.(encode auth_context, decode auth_context)
        in
        (match encode_decode with
         | None -> Rpc.Transport.of_reader_writer ~max_message_size reader writer
         | Some (encode, decode) ->
           let reader =
             Async_rpc_kernel.Rpc.Transport.Reader.pack
               (module Reader)
               { reader; decode; max_message_size }
           in
           let writer =
             Async_rpc_kernel.Rpc.Transport.Writer.pack
               (module Writer)
               (Writer.create
                  ~writer
                  ~encode
                  ~max_message_size
                  ~on_done_with_internal_buffer)
           in
           { Async_rpc_kernel.Rpc.Transport.reader; writer })
    in
    return (Ok transport)
  | (`Versioned 1 | `Versioned 0) as negotiated_protocol_version ->
    (match on_done_with_internal_buffer with
     | `Zero ->
       return
         (error_s
            [%message
              "Can't guarantee buffer zeroing with negotiated protocol version"
                ~required_protocol_version:(`Versioned 2 : [ `Versioned of int ])
                (negotiated_protocol_version : [ `Versioned of int ])])
     | `Do_nothing ->
       let%bind kerberized_rw = Kerberized_rw.create connection in
       let reader = Kerberized_rw.plaintext_reader kerberized_rw in
       let writer = Kerberized_rw.plaintext_writer kerberized_rw in
       let transport = Rpc.Transport.of_reader_writer reader writer ~max_message_size in
       return (Ok transport))
  | `Versioned (_ as version) ->
    Deferred.Or_error.error_s
      [%message
        "[Kerberised_rpc_transport.of_connection] got invalid protocol version"
          (version : int)]
;;

module Tcp = struct
  (* the point is that we only expose some functions. *)
  module Krb_ops = Protocol.Connection

  let handle_krb_client ?max_message_size ?on_done_with_internal_buffer handle_client =
    Staged.stage (fun addr connection ->
      match%bind
        of_connection ?max_message_size ?on_done_with_internal_buffer connection
      with
      | Error error ->
        (* let [Kerberized_tcp] give it to [on_handler_error]: *)
        Error.raise error
      | Ok transport -> handle_client addr transport connection)
  ;;

  let serve
        ?max_message_size
        ?max_connections
        ?backlog
        ?buffer_age_limit
        ?on_kerberos_error
        ?on_handshake_error
        ?on_handler_error
        ?on_connection
        ?on_done_with_internal_buffer
        ~where_to_listen
        ~krb_mode
        handle_client
    =
    Kerberized_tcp.Internal.Server.create
      ?max_connections
      ?backlog
      ?buffer_age_limit
      ?on_kerberos_error
      ?on_handshake_error
      ?on_handler_error
      ?on_connection
      ~krb_mode
      where_to_listen
      (Staged.unstage
         (handle_krb_client ?max_message_size ?on_done_with_internal_buffer handle_client))
  ;;

  let serve_with_anon
        ?max_message_size
        ?max_connections
        ?backlog
        ?buffer_age_limit
        ?on_kerberos_error
        ?on_handshake_error
        ?on_handler_error
        ?on_connection
        ?on_done_with_internal_buffer
        ~where_to_listen
        ~krb_mode
        handle_client
    =
    let handle_krb_client =
      handle_krb_client
        ?max_message_size
        ?on_done_with_internal_buffer
        (fun addr transport connection -> handle_client addr transport (Some connection))
      |> Staged.unstage
    in
    let handle_rpc_client addr (reader, writer) =
      let max_message_size =
        Option.value max_message_size ~default:default_max_message_size
      in
      let transport = Rpc.Transport.of_reader_writer ~max_message_size reader writer in
      handle_client addr transport None
    in
    Kerberized_tcp.Internal.Server.create_with_anon
      ?max_connections
      ?backlog
      ?buffer_age_limit
      ?on_kerberos_error
      ?on_handshake_error
      ?on_handler_error
      ?on_connection
      ~krb_mode
      where_to_listen
      (fun addr connection ->
         match (connection : Kerberized_tcp.Internal.Server.Krb_or_anon_conn.t) with
         | Krb connection -> handle_krb_client addr connection
         | Anon connection -> handle_rpc_client addr connection)
  ;;

  let create_handler
        ?max_message_size
        ?on_kerberos_error
        ?on_handshake_error
        ?on_handler_error
        ?on_connection
        ?on_done_with_internal_buffer
        ~krb_mode
        handle_client
    =
    Kerberized_tcp.Internal.Server.create_handler
      ?on_kerberos_error
      ?on_handshake_error
      ?on_handler_error
      ?on_connection
      ~krb_mode
      (handle_krb_client ?max_message_size ?on_done_with_internal_buffer handle_client
       |> Staged.unstage)
  ;;

  let client_internal
        ?override_supported_versions
        ?max_message_size
        ?timeout
        ?cred_cache
        ?buffer_age_limit
        ?on_connection
        ?on_done_with_internal_buffer
        ?krb_mode
        where_to_connect
    =
    let krb_mode =
      match krb_mode with
      | None -> Mode.Client.kerberized ()
      | Some krb_mode -> krb_mode
    in
    match%bind
      Kerberized_tcp.Internal.connect
        ?timeout:(Option.map ~f:Time_ns.Span.to_span_float_round_nearest timeout)
        ?cred_cache
        ?override_supported_versions
        ?on_connection
        ?buffer_age_limit
        ~krb_mode
        where_to_connect
    with
    | Error _ as error -> return error
    | Ok connection ->
      let%bind.Deferred.Or_error transport =
        of_connection ?max_message_size ?on_done_with_internal_buffer connection
      in
      return (Ok (transport, connection))
  ;;

  let client = client_internal ?override_supported_versions:None
end

module Internal = struct
  module Tcp = struct
    module Krb_ops = Protocol.Connection

    let client = Tcp.client_internal
  end
end
