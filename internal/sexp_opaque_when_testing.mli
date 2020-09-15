open! Core

(** [sexp_of_t t] is "<omitted-in-tests>" during inline tests *)

type 'a t = 'a [@@deriving sexp_of]
