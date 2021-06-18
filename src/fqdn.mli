open! Core
open Async

val localhost : string
val fqdn : string -> string Deferred.Or_error.t
