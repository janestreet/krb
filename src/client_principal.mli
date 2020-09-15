open! Core

type t = { client_principal : Principal.Name.t } [@@deriving sexp_of]
