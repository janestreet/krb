open! Core

type 'a t = 'a

let sexp_of_t sexp_of_a a =
  if Ppx_inline_test_lib.am_running then Sexp.Atom "<omitted-in-tests>" else sexp_of_a a
;;
