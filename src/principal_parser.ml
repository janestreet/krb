open! Core
open Import

module Result = struct
  type t =
    { primary : string
    ; instance : string option
    ; realm : string option
    }
  [@@deriving sexp_of]
end

let parse s =
  let split_or_fst ~on s =
    match String.rsplit2 ~on s with
    | None -> s, None
    | Some (fst, snd) -> fst, Some snd
  in
  let name, realm = split_or_fst ~on:'@' s in
  let primary, instance = split_or_fst ~on:'/' name in
  { Result.primary; instance; realm }
;;

let chop_default_domain hostname =
  match Config.default_domain with
  | None -> hostname
  | Some domain ->
    let suffix = "." ^ domain in
    Option.value ~default:hostname (String.chop_suffix ~suffix hostname)
;;

let%expect_test _ =
  let test s = parse s |> [%sexp_of: Result.t] |> print_s in
  test "foo";
  [%expect {| ((primary foo) (instance ()) (realm ())) |}];
  test "foo@BAZ.COM";
  [%expect {| ((primary foo) (instance ()) (realm (BAZ.COM))) |}];
  test "foo/bar";
  [%expect {| ((primary foo) (instance (bar)) (realm ())) |}];
  test "foo/bar@BAZ.COM";
  [%expect {| ((primary foo) (instance (bar)) (realm (BAZ.COM))) |}]
;;
