open! Core
open! Async

(* This has to be this way because of the way we handle TCP
   reader/writers. If we close the reader first, the writer ends up in an invalid
   state. If it still has data to flush, the next attempted write will raise. By
   making sure [Writer.close] finished, we know the [Writer.t] is flushed and it is
   safe for us to close the reader. *)
let close_connection_via_reader_and_writer reader writer =
  Writer.close writer ~force_close:(Clock.after (sec 30.))
  >>= fun () -> Reader.close reader
;;

let connect_and_handshake
      ?buffer_age_limit
      ?interrupt
      ?reader_buffer_size
      ?writer_buffer_size
      ?(timeout =
        Time_ns.Span.to_span_float_round_nearest
          Async_rpc_kernel.Async_rpc_kernel_private.default_handshake_timeout)
      where_to_connect
      ~handshake
  =
  Deferred.Or_error.try_with_join ~run:`Now ~rest:`Raise (fun () ->
    let finish_handshake_by = Time.add (Time.now ()) timeout in
    let%bind socket, tcp_reader, tcp_writer =
      Tcp.connect
        ?buffer_age_limit
        ?interrupt
        ?reader_buffer_size
        ?writer_buffer_size
        ~timeout
        where_to_connect
    in
    let timeout = Time.diff finish_handshake_by (Time.now ()) in
    let result = handshake ~socket ~tcp_reader ~tcp_writer in
    let return_error err =
      let%bind () = close_connection_via_reader_and_writer tcp_reader tcp_writer in
      Deferred.Or_error.fail
        (Error.tag err ~tag:"The server logs might have more information.")
    in
    match%bind Clock.with_timeout timeout result with
    | `Result (Ok res) -> Deferred.Or_error.return res
    | `Result (Error error) -> return_error error
    | `Timeout ->
      return_error
        (Error.create_s
           [%message "Timed out doing Krb.Rpc handshake" (timeout : Time.Span.t)]))
;;
