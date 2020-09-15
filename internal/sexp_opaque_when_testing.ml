open! Core

type 'a t = 'a

let sexp_of_t sexp_of_a a =
  if am_running_inline_test then Sexp.Atom "<omitted-in-tests>" else sexp_of_a a
;;
