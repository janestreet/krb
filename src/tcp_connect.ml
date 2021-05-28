open! Core
open! Async

let connect_and_handshake' ~timeout ~connect ~handshake ~on_handshake_error =
  Deferred.Or_error.try_with_join ~run:`Now ~rest:`Raise (fun () ->
    let finish_handshake_by = Time.add (Time.now ()) timeout in
    let%bind connect_ret = connect () in
    let timeout = Time.diff finish_handshake_by (Time.now ()) in
    let result = handshake connect_ret in
    let return_error err =
      let%bind () = on_handshake_error connect_ret in
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
      ?time_source
      where_to_connect
      ~handshake
  =
  connect_and_handshake'
    ~timeout
    ~connect:(fun () ->
      Tcp.connect
        ?buffer_age_limit
        ?interrupt
        ?reader_buffer_size
        ?writer_buffer_size
        ~timeout
        ?time_source
        where_to_connect)
    ~handshake:(fun (socket, tcp_reader, tcp_writer) ->
      handshake ~socket ~tcp_reader ~tcp_writer)
    ~on_handshake_error:(fun (_socket, tcp_reader, tcp_writer) ->
      close_connection_via_reader_and_writer tcp_reader tcp_writer)
;;

let connect_sock_and_handshake
      ?interrupt
      ?(timeout =
        Time_ns.Span.to_span_float_round_nearest
          Async_rpc_kernel.Async_rpc_kernel_private.default_handshake_timeout)
      ?time_source
      where_to_connect
      ~handshake
  =
  let open Deferred.Or_error.Let_syntax in
  connect_and_handshake'
    ~timeout
    ~connect:(fun () ->
      Tcp.connect_sock ?interrupt ~timeout ?time_source where_to_connect)
    ~handshake:(fun socket ->
      let%bind conn = handshake ~socket in
      return (conn, socket))
    ~on_handshake_error:(fun _socket -> Deferred.return ())
;;
