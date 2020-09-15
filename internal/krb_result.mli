open! Core

type 'a t = ('a, Krb_error.t) Result.t

val to_or_error : ?context:Context.t -> info:string -> 'a t -> 'a Or_error.t
