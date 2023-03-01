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
  Deferred.List.filter ~how:`Sequential entries ~f:(fun entry ->
    match%map.Deferred Internal.Keytab_entry.principal entry with
    | Error _ -> false
    | Ok entry_principal ->
      String.equal (Principal.to_string entry_principal) target_principal)
  |> Deferred.ok
;;

let validate keytab principal =
  let keytab_path_omitted_in_test keytab =
    if Ppx_inline_test_lib.am_running then "<omitted-in-tests>" else path keytab
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

module Stable_group = struct
  let group (type t) (module Class : Map.Key_plain with type t = t) ~equiv l =
    let module ClassMap = Map.Make_plain (Class) in
    let with_class = List.map l ~f:(fun e -> equiv e, e) in
    let first_occurences =
      List.foldi with_class ~init:ClassMap.empty ~f:(fun i indexes (_class, _) ->
        match Map.add ~key:_class ~data:i indexes with
        | `Ok indexes -> indexes
        | `Duplicate -> indexes)
    in
    List.Assoc.sort_and_group with_class ~compare:(fun a b ->
      Comparable.lift
        Int.compare
        ~f:(fun _class -> Map.find_exn first_occurences _class)
        a
        b)
  ;;

  let%expect_test "stable_group" =
    let open Deferred.Let_syntax in
    group (module Int) ~equiv:(fun i -> i % 3) [ 1; 2; 3; 4; 5; 6; 7; 8; 9; 10 ]
    |> [%sexp_of: (int, int list) List.Assoc.t]
    |> print_s;
    [%expect {| ((1 (1 4 7 10)) (2 (2 5 8)) (0 (3 6 9))) |}];
    return ()
  ;;
end

let latest_keys keytab =
  (* For the latest kvno, group keys by and encryption type. This ought to be sufficient to
     determine the key, which is a function of the encryption type and the password "named"
     by the latest kvno. *)
  let%bind latest_kvno, entries =
    Deferred.Or_error.try_with_join (fun () -> entries_by_kvno keytab >>| Map.max_elt_exn)
  in
  let%bind keyblocks =
    Deferred.Or_error.List.map ~how:`Sequential entries ~f:(fun entry ->
      Internal.Keytab_entry.keyblock entry)
    >>| (* We want to preserve the order of the encryption types to keep
           keytabs easy to inspect.*)
    Stable_group.group (module Internal.Enctype) ~equiv:Internal.Keyblock.enctype
    >>= Deferred.Or_error.List.map ~how:`Sequential ~f:(fun (enctype, keyblocks) ->
      match
        List.dedup_and_sort ~compare:[%compare: Internal.Keyblock.t] keyblocks
      with
      | [] -> assert false
      | [ keyblock ] -> return keyblock
      | _ :: _ :: _ ->
        Deferred.Or_error.error_s
          [%message
            "conflicting keys" (latest_kvno : int) (enctype : Internal.Enctype.t)])
  in
  return (latest_kvno, keyblocks)
;;

let add_spn t spn =
  let%bind kvno, keyblocks = latest_keys t in
  let%bind new_principal = Principal.create spn in
  Deferred.Or_error.List.iter ~how:`Sequential keyblocks ~f:(fun keyblock ->
    let%bind entry = Internal.Keytab_entry.create new_principal ~kvno keyblock in
    add_entry t entry)
;;

let remove_spn t spn =
  let%bind entries = Internal.Keytab.entries t in
  let%bind to_remove =
    Deferred.Or_error.List.filter ~how:`Sequential entries ~f:(fun entry ->
      let%bind entry_principal =
        Internal.Keytab_entry.principal entry >>| Principal.name
      in
      return ([%compare.equal: Principal.Name.t] entry_principal spn))
  in
  Deferred.Or_error.List.iter ~how:`Sequential to_remove ~f:(fun entry ->
    remove_entry t entry)
;;

let add_entry t ~password ~enctype ~kvno ~principal =
  let%bind salt = Internal.Principal.salt principal in
  let%bind keyblock = Internal.Keyblock.create enctype ~password ~salt in
  let%bind entry = Internal.Keytab_entry.create principal ~kvno keyblock in
  add_entry t entry
;;

let update_user_keytab_entries t ~user_entries ~password ~kvno =
  let open Deferred.Or_error.Let_syntax in
  Deferred.Or_error.List.iter ~how:`Sequential user_entries ~f:(fun user_entry ->
    let%bind old_keyblock = Internal.Keytab_entry.keyblock user_entry in
    let enctype = Internal.Keyblock.enctype old_keyblock in
    let%bind principal = Internal.Keytab_entry.principal user_entry in
    add_entry t ~password ~enctype ~kvno ~principal)
;;

let add_new_entry_for_all_principals ?kvno t ~password =
  let%bind latest_keytab_kvno, entries = entries_by_kvno t >>| Map.max_elt_exn in
  let kvno = Option.value kvno ~default:(latest_keytab_kvno + 1) in
  let%bind principals_and_entries =
    Deferred.Or_error.List.map ~how:`Sequential entries ~f:(fun entry ->
      let%map principal_name =
        Internal.Keytab_entry.principal entry >>| Principal.name
      in
      principal_name, entry)
  in
  let spns =
    List.filter_map principals_and_entries ~f:(function principal, _ ->
      (match principal with
       | User _ -> None
       | Service _ -> Some principal))
    |> List.dedup_and_sort ~compare:[%compare: Principal.Name.t]
  in
  let%bind user_entries =
    match
      List.filter_map principals_and_entries ~f:(fun (principal, entry) ->
        match principal with
        | User _ -> Some (principal, entry)
        | Service _ -> None)
      |> List.Assoc.sort_and_group ~compare:[%compare: Principal.Name.t]
    with
    | [ (_, entries) ] -> return entries
    | [] -> Deferred.Or_error.error_s [%message "Missing user principal in keytab."]
    | entries_and_principals ->
      let principals = List.map entries_and_principals ~f:fst in
      Deferred.Or_error.error_s
        [%message
          "Multliple user principals in keytab." (principals : Principal.Name.t list)]
  in
  let%bind (_ : int * Internal.Keyblock.t list) =
    (* Ensure that for the latest kvno, all principals have the same keyblock
       for each encryption type. It's important that we do this before we modify
       the keytab and bump the kvno! *)
    latest_keys t
  in
  let%bind () = update_user_keytab_entries t ~user_entries ~password ~kvno in
  let%bind () =
    Deferred.Or_error.List.iter ~how:`Sequential spns ~f:(fun spn -> add_spn t spn)
  in
  return ()
;;
