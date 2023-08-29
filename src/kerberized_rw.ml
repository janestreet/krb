open! Core
open! Async
open Import.Internal

(* The kerberized reader and writer work as follows:

   Writes to the kerberized writer are batched together at some "reasonable" granularity
   and transformed (encrypted or checksum'd) if necessary.  If transformed, the message is
   written using the standard bin-prot "size-prefixed binary protocol".

   Reading from the kerberized writer then does the inverse, reading and decoding each
   batch. *)

type t =
  { plaintext_reader : Reader.t
  ; plaintext_writer : Writer.t
  ; writer_closed_and_flushed : unit Deferred.t
  }
[@@deriving fields ~getters]

let make_reader_writer info =
  (* borrowed from [Reader.of_pipe] *)
  Unix.pipe info
  >>| fun (`Reader reader_fd, `Writer writer_fd) ->
  let reader = Reader.create reader_fd in
  let writer =
    Writer.create ~buffer_age_limit:`Unlimited ~raise_when_consumer_leaves:false writer_fd
  in
  reader, writer
;;

let can_actually_write writer = Writer.can_write writer && Writer.fd writer |> Fd.is_open

let create_writer conn_type auth_context writer =
  let transformation =
    match (conn_type : Conn_type.t) with
    | Auth -> None
    | Safe -> Some Auth_context.Safe.encode
    | Priv -> Some Auth_context.Priv.encode
  in
  match transformation with
  | None -> return (writer, `Closed_and_flushed_downstream (Writer.close_finished writer))
  | Some transformation ->
    let info = Info.create "Kerberos encryption" (Writer.id writer) Writer.Id.sexp_of_t in
    make_reader_writer info
    >>| fun (plaintext_r, plaintext_w) ->
    let monitor = Writer.monitor plaintext_w in
    Monitor.detach_and_iter_errors (Writer.monitor writer) ~f:(Monitor.send_exn monitor);
    let downstream_closed =
      Writer.close_finished writer
      >>= fun () ->
      Deferred.all_unit [ Writer.close plaintext_w; Reader.close plaintext_r ]
    in
    don't_wait_for
      (let handle_chunk buf ~pos ~len =
         transformation auth_context (Bigsubstring.create ~pos ~len buf)
         >>| ok_exn
         >>| fun bstr ->
         match can_actually_write writer with
         | false -> `Stop ()
         | true ->
           Writer.write_bin_prot writer Bigstring.Stable.V1.bin_writer_t bstr;
           `Continue
       in
       Monitor.try_with
         ~run:`Schedule
         ~name:"Kerberized_rw.create_writer"
         (fun () ->
            Reader.read_one_chunk_at_a_time plaintext_r ~handle_chunk
            >>| function
            | `Eof | `Stopped () -> ()
            | `Eof_with_unconsumed_data _ ->
              failwith "Impossible b/c we always consume all data above.")
       >>| (function
         | Ok () -> ()
         | Error exn -> Monitor.send_exn monitor exn)
       >>= fun () ->
       Deferred.all_unit [ Reader.close plaintext_r; Writer.close plaintext_w ]
       >>= fun () -> Writer.close writer);
    plaintext_w, `Closed_and_flushed_downstream downstream_closed
;;

let reader_read_all reader read_one =
  let pipe_r, pipe_w = Pipe.create () in
  let finished =
    Deferred.repeat_until_finished () (fun () ->
      match%bind read_one reader with
      | `Eof -> return (`Finished ())
      | `Ok one ->
        if Pipe.is_closed pipe_w
        then return (`Finished ())
        else (
          let%map () = Pipe.write pipe_w one in
          `Repeat ()))
  in
  upon finished (fun () -> Pipe.close pipe_w);
  pipe_r
;;

let create_reader conn_type auth_context ~writer reader =
  let transformation =
    match (conn_type : Conn_type.t) with
    | Auth -> None
    | Safe -> Some Auth_context.Safe.decode
    | Priv -> Some Auth_context.Priv.decode
  in
  match transformation with
  | None -> return reader
  | Some transformation ->
    let info = Info.create "Kerberos decryption" (Reader.id reader) Reader.Id.sexp_of_t in
    make_reader_writer info
    >>| fun (plaintext_r, plaintext_w) ->
    (* If the new writer receives an error on its monitor, pass it on to the old writer's
       monitor. [create_writer] will then in turn take it out of that monitor, and stuff
       it into the monitor of the plaintext writer (the one that we hand to the user, not
       the one here) *)
    let monitor = Writer.monitor writer in
    Monitor.detach_and_iter_errors
      (Writer.monitor plaintext_w)
      ~f:(Monitor.send_exn monitor);
    don't_wait_for
      (Monitor.try_with_or_error
         ~here:[%here]
         ~name:"Kerberized_rw.create_reader"
         (fun () ->
            let pipe =
              reader_read_all reader (fun r ->
                Reader.read_bin_prot r Bigstring.Stable.V1.bin_reader_t)
            in
            Pipe.fold' pipe ~init:(Ok ()) ~f:(fun result ts ->
              if Writer.can_write plaintext_w
              then
                Deferred.Queue.fold ts ~init:result ~f:(fun result t ->
                  return result
                  >>=? fun () ->
                  transformation auth_context (Bigsubstring.create t)
                  >>|? fun bstr ->
                  if can_actually_write plaintext_w
                  then Writer.write_bigstring plaintext_w bstr)
              else
                (* Silently drop anything left if the writer is closed as that's the least
                   bad thing *)
                return result))
       >>| (function
         | Ok (Ok ()) -> ()
         | Ok (Error krb_error) ->
           Error.tag ~tag:"kerberos decryption failed" krb_error
           |> Error.to_exn
           |> Monitor.send_exn monitor
         | Error e -> Monitor.send_exn monitor (Error.to_exn e))
       >>= fun () ->
       Writer.close writer
       >>= fun () -> Reader.close reader >>= fun () -> Writer.close plaintext_w);
    plaintext_r
;;

let create connection =
  let conn_type = Async_protocol.Connection.conn_type connection in
  let reader = Async_protocol.Connection.reader connection in
  let writer = Async_protocol.Connection.writer connection in
  match Async_protocol.Connection.auth_context connection with
  | `Test_mode ->
    return
      { plaintext_reader = reader
      ; plaintext_writer = writer
      ; writer_closed_and_flushed = Writer.close_finished writer
      }
  | `Prod auth_context ->
    Deferred.both
      (create_reader conn_type auth_context ~writer reader)
      (create_writer conn_type auth_context writer)
    >>| fun ( plaintext_reader
            , (plaintext_writer, `Closed_and_flushed_downstream writer_closed_and_flushed)
            ) ->
    { plaintext_reader; plaintext_writer; writer_closed_and_flushed }
;;
