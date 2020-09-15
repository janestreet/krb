module Stable = struct
  open! Core.Core_stable

  module Path = struct
    module V1 = struct
      type t =
        | User
        | Host
        | File of string
      [@@deriving bin_io, compare, hash, sexp]
    end
  end
end

open! Core
open Import

module Path = struct
  type t = Stable.Path.V1.t =
    | User
    | Host
    | File of string
  [@@deriving compare, hash, sexp_of]

  let user_keytab ~user = Config.user_keytab_dir ~username:user ^/ user ^ ".keytab"

  let filename = function
    | Host -> Config.host_keytab_path
    | File path -> path
    | User ->
      let passwd = Currently_running_user.Blocking.passwd () in
      user_keytab ~user:passwd.name
  ;;

  let to_keytab t = Internal.Keytab.load (filename t)
  let grammar = "(user-keytab|host-keytab|PATH)"

  let arg =
    Command.Arg_type.create (function
      | "user-keytab" -> User
      | "host-keytab" -> Host
      | path -> File path)
  ;;

  let anon = Command.Param.(grammar %: arg)

  let make_flag flag_type =
    Command.Param.(flag "keytab" (flag_type arg) ~doc:(grammar ^ " kerberos keytab file"))
  ;;

  let flag = make_flag Command.Param.required
  let optional_flag = make_flag Command.Param.optional
end

open Async
open Deferred.Or_error.Let_syntax
include Internal.Keytab

let load = Path.to_keytab

(* shadows Internal.Keytab.load *)

let entries_by_kvno keytab =
  let%bind entries = entries keytab in
  List.map entries ~f:(fun entry -> Internal.Keytab_entry.kvno entry, entry)
  |> Int.Map.of_alist_multi
  |> return
;;

let entries_for_principal keytab principal =
  let target_principal = Principal.to_string principal in
  let%bind entries = entries keytab in
  Deferred.List.filter entries ~f:(fun entry ->
    match%map.Deferred Internal.Keytab_entry.principal entry with
    | Error _ -> false
    | Ok entry_principal ->
      String.equal (Principal.to_string entry_principal) target_principal)
  |> Deferred.ok
;;

let validate keytab principal =
  let keytab_path_omitted_in_test keytab =
    if am_running_inline_test then "<omitted-in-tests>" else path keytab
  in
  let keytab_advice =
    "You should probably use [Krb.Mode.Server.kerberized ()], which does proper \
     validation.\n\
     If you are using this function already, please report this to krb-dev@janestreet.com"
  in
  let invalid_keytab_error keytab error =
    [%message
      "Unable to read entries from keytab."
        ~keytab_path:(keytab_path_omitted_in_test keytab : string)
        (error : Error.t)
        "Make sure the keytab path is correct and you have permission to read the file."
        keytab_advice]
  in
  let no_matching_keytab_entry keytab ~principal =
    [%message
      "The keytab has no entry for principal."
        ~keytab_path:(keytab_path_omitted_in_test keytab : string)
        (principal : string)
        "Make sure the keytab path is correct."
        keytab_advice]
  in
  match%map.Deferred entries_for_principal keytab principal with
  | Error error -> Or_error.error_s (invalid_keytab_error keytab error)
  | Ok [] ->
    Or_error.error_s
      (no_matching_keytab_entry
         keytab
         ~principal:(Internal.Principal.to_string principal))
  | Ok _ -> Ok ()
;;

let validate_path keytab_path principal_name =
  let%bind keytab = load keytab_path in
  let%bind principal = Principal.create principal_name in
  validate keytab principal
;;

(* group keys by kvno and encryption type.  These two ought to be sufficient to determine
   the key, which is a function of the encryption type and the password "named" by the
   kvno. *)
let latest_keys keytab =
  let%bind entries_by_kvno = entries_by_kvno keytab in
  let open Deferred.Let_syntax in
  with_return (fun { return } ->
    Deferred.Map.mapi entries_by_kvno ~f:(fun ~key:kvno ~data:entries ->
      Deferred.List.map entries ~f:(fun entry ->
        Internal.Keytab_entry.keyblock entry
        >>| ok_exn
        >>| fun keyblock -> Internal.Keyblock.enctype keyblock, keyblock)
      >>| Internal.Enctype.Map.of_alist_multi
      >>| Map.mapi ~f:(fun ~key:enctype ~data:keyblocks ->
        match
          List.dedup_and_sort ~compare:[%compare: Internal.Keyblock.t] keyblocks
        with
        | [] -> assert false
        | [ keyblock ] -> keyblock
        | _ :: _ :: _ as keyblocks ->
          let keys = List.map ~f:Internal.Keyblock.key keyblocks in
          return
          @@ Deferred.return
          @@ error_s
               [%message
                 "conflicting keys"
                   (kvno : int)
                   (enctype : Internal.Enctype.t)
                   (keys : string list)])
      >>| Map.data)
    >>| Map.max_elt_exn
    >>| Result.return)
;;

let add_spn t ~service ~hostname =
  let%bind kvno, keyblocks = latest_keys t in
  let spn = Principal.Name.Service { service; hostname } in
  let%bind new_principal = Principal.create spn in
  Deferred.Or_error.List.iter keyblocks ~f:(fun keyblock ->
    let%bind entry = Internal.Keytab_entry.create new_principal ~kvno keyblock in
    add_entry t entry)
;;

let remove_spn t ~service ~hostname =
  let spn = Principal.Name.Service { service; hostname } in
  let%bind entries = Internal.Keytab.entries t in
  let%bind to_remove =
    Deferred.Or_error.List.filter entries ~f:(fun entry ->
      let%bind entry_principal =
        Internal.Keytab_entry.principal entry >>| Principal.name
      in
      return ([%compare.equal: Principal.Name.t] entry_principal spn))
  in
  Deferred.Or_error.List.iter to_remove ~f:(fun entry -> remove_entry t entry)
;;

let add_entry t ~password ~enctype ~kvno ~principal =
  let%bind salt = Internal.Principal.salt principal in
  let%bind keyblock = Internal.Keyblock.create enctype ~password ~salt in
  let%bind entry = Internal.Keytab_entry.create principal ~kvno keyblock in
  add_entry t entry
;;
