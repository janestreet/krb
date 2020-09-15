open Core
open Async

let inet_of_fd ~f:sockaddr_of_fd fd =
  let fd = Fd.file_descr_exn fd in
  match (sockaddr_of_fd fd : Core.Unix.sockaddr) with
  | ADDR_UNIX _ -> failwith "Not an inet socket"
  | ADDR_INET (inet, port) -> `Inet (inet, port)
;;

let local_exn = inet_of_fd ~f:Core.Unix.getsockname
let remote_exn = inet_of_fd ~f:Core.Unix.getpeername
