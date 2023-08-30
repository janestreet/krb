module Stable = struct
  open Core.Core_stable

  module V1 = struct
    module T = struct
      type t =
        | Auth
        | Safe
        | Priv
      [@@deriving bin_io, compare, sexp]

      include (val Comparator.V1.make ~compare ~sexp_of_t)
    end

    include T
    include Comparable.V1.Make (T)
  end
end

open! Core

module T = struct
  type t = Stable.V1.t =
    | Auth
    | Safe
    | Priv
  [@@deriving compare, enumerate, hash, sexp]

  type comparator_witness = Stable.V1.comparator_witness

  let comparator = Stable.V1.comparator
end

include T
include Comparable.Make_plain_using_comparator (T)
include Sexpable.To_stringable (T)

let to_string t = String.lowercase (to_string t)

let strength = function
  | Auth -> 0
  | Safe -> 1
  | Priv -> 2
;;

let strongest = Core.Set.max_elt

let negotiate_strongest ~us ~peer =
  Core.Set.inter us peer
  |> strongest
  |> function
  | Some t -> Ok t
  | None ->
    Or_error.error_s
      [%message
        "No shared connection types between us and our peer" (us : Set.t) (peer : Set.t)]
;;

let is_as_strong client ~as_:server = Int.(strength client >= strength server)
let%test "is_as_strong reflexive" = List.for_all all ~f:(fun t -> is_as_strong t ~as_:t)

let%test "is_as_strong" =
  let is_not_as_strong a ~as_:b = not (is_as_strong a ~as_:b) in
  List.for_all
    ~f:Fn.id
    [ (* Priv is strongest *)
      is_as_strong Priv ~as_:Auth
    ; is_as_strong Priv ~as_:Safe
    ; (* Auth is weakest *)
      is_not_as_strong Auth ~as_:Safe
    ; is_not_as_strong Auth ~as_:Priv
    ; (* Safe is in between *)
      is_as_strong Safe ~as_:Auth
    ; is_not_as_strong Safe ~as_:Priv
    ]
;;

module Deprecated = struct
  let arg_type =
    Command.Arg_type.create of_string
    |> Command.Arg_type.comma_separated ~allow_empty:true
  ;;

  let make_flag required_or_optional =
    let open Command.Param in
    flag
      "conn-types"
      (required_or_optional arg_type)
      ~doc:
        "(auth|safe|priv) What kind of Kerberos connection to use (specify multiple \
         separated by comma)"
  ;;

  let flag = make_flag Command.Param.required
  let optional_flag = make_flag Command.Param.optional
end
