open! Core

type t

external free : Context.t -> t -> unit = "caml_krb5_free_data_contents"
