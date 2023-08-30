open! Core
open Async

(** [Get_init_creds_opts.t] stores options for getting credentials from the KDC. It
    is used to change ticket lifetimes and flags for requested tickets. *)

(** [krb5_get_init_creds_opt] *)
type t

val create
  :  ?tkt_lifetime:Time_float.Span.t (** default: 10h *)
  -> ?renew_lifetime:Time_float.Span.t
       (** default: 365d (but most likely shortened by KDC) *)
  -> ?forwardable:bool (** default: true *)
  -> ?proxiable:bool (** default: false *)
  -> unit
  -> t

val default : t

module Raw : sig
  type t

  val free : Context.t -> t -> unit
end

val to_raw : t -> Raw.t Deferred.Or_error.t
