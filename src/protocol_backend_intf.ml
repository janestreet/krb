open Core
open Async
open! Import

(** [Protocol_backend.S] is a signature of a module providing binprot reading and writing
    which [Protocol] uses for initial handshake. *)
module type S = sig
  type t

  val write_bin_prot : t -> 'a Bin_prot.Type_class.writer -> 'a -> unit

  val read_bin_prot
    :  t
    -> 'a Bin_prot.Type_class.reader
    -> [ `Ok of 'a | `Eof ] Deferred.t

  val info : t -> Info.t
  val local_inet : t -> Socket.Address.Inet.t
  val remote_inet : t -> Socket.Address.Inet.t
end
