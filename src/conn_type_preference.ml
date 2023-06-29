module Stable = struct
  open Core.Core_stable

  module V1 = struct
    module T = struct
      type t =
        | Prefer of Conn_type.Stable.V1.t list
        | Any of Conn_type.Stable.V1.Set.t
      [@@deriving bin_io, compare, sexp]
    end

    module C = Comparator.V1.Make (T)
    include T
    include C

    include Comparable.V1.Make (struct
        include T
        include C
      end)
  end
end

open! Core

module Conn_type_set = struct
  include Conn_type.Set
  include Provide_hash (Conn_type)
end

type t = Stable.V1.t =
  | Prefer of Conn_type.t list
  | Any of Conn_type_set.t
[@@deriving compare, hash, sexp_of]

let any conn_types = Any (Conn_type.Set.of_list conn_types)
let accept_all = any Conn_type.all
let accept_safe_priv = any [ Priv; Safe ]
let accept_only conn_type = any [ conn_type ]
let prefer_speed = Prefer [ Auth; Safe; Priv ]
let prefer_strength = Prefer [ Priv; Safe; Auth ]

let to_set = function
  | Prefer conn_types -> Conn_type.Set.of_list conn_types
  | Any conn_types -> conn_types
;;

let filter_against_peer lst ~peer =
  let mem =
    match peer with
    | Any a -> Set.mem a
    | Prefer p -> List.mem p ~equal:Conn_type.equal
  in
  List.filter lst ~f:mem
;;

let filter pref ~only_in =
  match pref with
  | Any conn_types ->
    Any
      (Set.to_list conn_types
       |> filter_against_peer ~peer:only_in
       |> Conn_type_set.of_list)
  | Prefer conn_types -> Prefer (filter_against_peer conn_types ~peer:only_in)
;;

let negotiate ~us ~peer =
  match us, peer with
  | Any us, Any peer -> Conn_type.negotiate_strongest ~us ~peer
  | Any a, Prefer p | Prefer p, Any a ->
    (match filter_against_peer p ~peer:(Any a) with
     | [] ->
       Or_error.error_s
         [%message
           "No shared connection types between us and our peer" (us : t) (peer : t)]
     | hd :: _ -> Ok hd)
  | Prefer p_us, Prefer p_peer ->
    let us_filtered = filter_against_peer p_us ~peer:(Prefer p_peer) in
    let peer_filtered = filter_against_peer p_peer ~peer:(Prefer p_us) in
    (match us_filtered, peer_filtered with
     | hd1 :: _, hd2 :: _ when [%compare.equal: Conn_type.t] hd1 hd2 -> Ok hd1
     | _ ->
       Conn_type.negotiate_strongest
         ~us:(Conn_type.Set.of_list p_us)
         ~peer:(Conn_type.Set.of_list p_peer))
;;

module Deprecated = struct
  let arg_type =
    Command.Arg_type.create Conn_type.of_string
    |> Command.Arg_type.comma_separated ~allow_empty:true
  ;;

  let optional_prefer_flag =
    let open Command.Param in
    flag
      "conn-types-prefer"
      (optional arg_type)
      ~doc:
        "(auth|safe|priv) The connection types are ordered and express a preference \
         (specify multiple separated by comma)"
  ;;

  let optional_flag =
    let open Command.Param in
    choose_one
      ~if_nothing_chosen:(Default_to None)
      [ Conn_type.Deprecated.optional_flag
        |> map ~f:(Option.map ~f:(fun x -> Some (Any (Conn_type.Set.of_list x))))
      ; optional_prefer_flag |> map ~f:(Option.map ~f:(fun x -> Some (Prefer x)))
      ]
  ;;

  let flag =
    let message = "Must specify one of [-conn-types] or [-conn-types-prefer]" in
    Command.Param.map optional_flag ~f:(fun x -> Option.value_exn ~message x)
  ;;
end

let%test_unit "negotiate" =
  let test ~us ~peer ~(expect : Conn_type.t) =
    let result = negotiate ~us ~peer |> ok_exn in
    [%test_result: Conn_type.t] result ~expect
  in
  let test_expect_fail ~us ~peer =
    negotiate ~us ~peer
    |> function
    | Error _ -> ()
    | Ok negotiated ->
      Error.raise_s
        [%message
          "Expected this negotiation to fail"
            (us : t)
            (peer : t)
            (negotiated : Conn_type.t)]
  in
  (* Any/Any *)
  test ~us:(any [ Auth ]) ~peer:(any [ Auth ]) ~expect:Auth;
  test ~us:(any [ Auth ]) ~peer:(any [ Priv; Safe; Auth ]) ~expect:Auth;
  test_expect_fail ~us:(any [ Auth ]) ~peer:(any [ Priv; Safe ]);
  test ~us:(any [ Priv; Safe; Auth ]) ~peer:(any [ Priv; Safe; Auth ]) ~expect:Priv;
  (* Any/Prefer *)
  test ~us:(any [ Auth ]) ~peer:(Prefer [ Auth ]) ~expect:Auth;
  test ~us:(any [ Auth ]) ~peer:(Prefer [ Priv; Safe; Auth ]) ~expect:Auth;
  test_expect_fail ~us:(any [ Auth ]) ~peer:(Prefer [ Priv; Safe ]);
  test ~us:(any [ Priv; Safe; Auth ]) ~peer:(Prefer [ Priv; Safe; Auth ]) ~expect:Priv;
  test ~us:(any [ Priv; Safe; Auth ]) ~peer:(Prefer [ Auth; Safe; Priv ]) ~expect:Auth;
  (* Prefer/Prefer *)
  test ~us:(Prefer [ Auth ]) ~peer:(Prefer [ Auth ]) ~expect:Auth;
  test ~us:(Prefer [ Auth ]) ~peer:(Prefer [ Priv; Safe; Auth ]) ~expect:Auth;
  test_expect_fail ~us:(Prefer [ Auth ]) ~peer:(Prefer [ Priv; Safe ]);
  test ~us:(Prefer [ Priv; Safe; Auth ]) ~peer:(Prefer [ Priv; Safe; Auth ]) ~expect:Priv;
  test ~us:(Prefer [ Auth; Priv; Safe ]) ~peer:(Prefer [ Priv; Safe; Auth ]) ~expect:Priv;
  test ~us:(Prefer [ Auth; Priv; Safe ]) ~peer:(Prefer [ Auth; Priv; Safe ]) ~expect:Auth;
  test ~us:(Prefer [ Auth; Safe; Priv ]) ~peer:(Prefer [ Safe; Auth; Priv ]) ~expect:Priv;
  test ~us:(Prefer [ Auth; Safe; Priv ]) ~peer:(Prefer [ Safe; Priv ]) ~expect:Safe
;;
