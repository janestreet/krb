open! Core
open! Async

val local_exn : Fd.t -> Socket.Address.Inet.t
val remote_exn : Fd.t -> Socket.Address.Inet.t
