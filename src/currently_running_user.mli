open! Core
open Async

(** lib/krb makes some decisions based on the currently running user. In order to play
    nicely with setuid programs, it uses the effective UID. *)

val passwd : unit -> Unix.Passwd.t Deferred.t
val name : unit -> string Deferred.t

module Blocking : sig
  val passwd : unit -> Unix.Passwd.t
  val name : unit -> string
end
