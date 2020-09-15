open! Core
open Async

type 'a t =
  { function_ : string
  ; tag_arguments : Sexp.t Lazy.t option
  ; tag_result : ('a -> Sexp.t) option
  ; tag_error : (Krb_error.t -> Sexp.t Deferred.t) option
  }

let create ?tag_arguments ?tag_result ?tag_error function_ =
  { function_; tag_arguments; tag_result; tag_error }
;;

let tags' t code =
  let%map error_tags =
    match t.tag_error with
    | None -> return None
    | Some get_tags -> get_tags code >>| Option.some
  in
  match Config.verbose_errors with
  | false -> error_tags
  | true ->
    let argument_tags = Option.map t.tag_arguments ~f:Lazy.force in
    (match Option.to_list argument_tags @ Option.to_list error_tags with
     | [] -> None
     | tags -> Some [%message (code : Krb_error.t) ~_:(tags : Sexp.t list)])
;;

let sandbox_tag =
  Option.some_if
    (am_running_inline_test && not Config.am_sandboxed)
    (Sexp.Atom
       "No KDC access - consider setting (uses_kerberos (Yes_with_principals \
        (PRINCIPALS...))) in the appropriate portion of the jbuild to opt-in to \
        sandboxing")
;;

let tags =
  match sandbox_tag with
  | None -> tags'
  | Some sandbox_tag ->
    fun t code ->
      let%map tags = tags' t code >>| Option.to_list in
      Some (Sexp.List (sandbox_tag :: tags))
;;
