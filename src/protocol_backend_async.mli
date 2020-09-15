(** The original async reader/writer-based backend implementation. *)

open Core
open Async
include Protocol_backend_intf.S

val create : reader:Reader.t -> writer:Writer.t -> t Or_error.t
val reader : t -> Reader.t
val writer : t -> Writer.t
