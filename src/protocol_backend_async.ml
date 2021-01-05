open Core
open Async
open Import
module Inet_of_fd = Internal.Inet_of_fd

type t =
  { reader : Reader.t
  ; writer : Writer.t
  }
[@@deriving fields]

let create ~reader ~writer =
  let open Or_error.Let_syntax in
  (* to_int_exn will raise if fd is already closed, which is exactly what we want *)
  let%bind reader_fd_int =
    Or_error.try_with (fun () -> Reader.fd reader |> Fd.to_int_exn)
  in
  let%bind writer_fd_int =
    Or_error.try_with (fun () -> Writer.fd writer |> Fd.to_int_exn)
  in
  if reader_fd_int <> writer_fd_int
  then
    Or_error.error_s
      [%message
        "Reader and writer have different fds" (reader_fd_int : int) (writer_fd_int : int)]
  else Ok { reader; writer }
;;

let write_bin_prot_exn (t : t) = Writer.write_bin_prot t.writer
let read_bin_prot (t : t) = Reader.read_bin_prot t.reader
let info t = Reader.fd t.reader |> Fd.info
let local_inet t = Inet_of_fd.local_exn (Writer.fd t.writer)
let remote_inet t = Inet_of_fd.remote_exn (Writer.fd t.writer)
