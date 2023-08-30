open! Core
open Async

let localhost = "localhost"

let fqdn host =
  match%map
    Async.Unix.Addr_info.get
      ~host
      [ AI_SOCKTYPE Unix.SOCK_STREAM; AI_FAMILY Unix.PF_INET; AI_CANONNAME ]
    >>| List.map ~f:(fun (info : Core_unix.addr_info) -> info.ai_canonname)
    (* This filtering avoids using canonical names when those are not merely qualified
       versions of the host.

    *)
    >>| List.filter ~f:(fun potential_fqdn ->
          match String.chop_prefix potential_fqdn ~prefix:host with
          | None -> false
          | Some "" -> true
          | Some suffix -> String.is_prefix suffix ~prefix:".")
  with
  | [] -> Or_error.errorf "No canonical name found for [%s]" host
  | [ fqdn ] -> Ok fqdn
  | _ -> Or_error.errorf "Too many results returned for [%s]" host
;;
