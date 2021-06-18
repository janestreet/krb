(** A kerberos realm *)

open! Core
open Async

type t = string [@@deriving bin_io, compare, hash, sexp]

val default : unit -> t Deferred.Or_error.t
