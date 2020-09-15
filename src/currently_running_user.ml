open! Core
open Async

let passwd () = Unix.Passwd.getbyuid_exn (Unix.geteuid ())

let name () =
  let%bind passwd = passwd () in
  return passwd.name
;;

module Blocking = struct
  let passwd () = Core.Unix.Passwd.getbyuid_exn (Core.Unix.geteuid ())
  let name () = (passwd ()).name
end
