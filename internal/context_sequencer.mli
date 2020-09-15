open! Core
open Async

(** Sequence all kerberos functions. We use a global context (in C land) and there are
    some functions that are not thread safe. We even have to sequence the finalizers
    because they too call functions that need a context. *)

val enqueue_job_exn : f:(Context.t -> 'a) -> 'a Deferred.t

val enqueue_job_with_info'
  :  info:'a Krb_info.t
  -> f:(Context.t -> 'a Krb_result.t)
  -> ('a, [ `Raised of Error.t | `Krb_error of Error.t * Krb_error.t ]) Deferred.Result.t

val enqueue_job_with_info
  :  info:'a Krb_info.t
  -> f:(Context.t -> 'a Krb_result.t)
  -> 'a Or_error.t Deferred.t

val enqueue_blocking_if_below_encryption_size_threshold
  :  data_size:int
  -> info:'a Krb_info.t
  -> f:(Context.t -> 'a Krb_result.t)
  -> 'a Or_error.t Deferred.t

val add_finalizer : 'a -> f:(Context.t -> 'a -> unit) -> unit

module Expert : sig
  val enqueue_job_with_info_blocking
    :  info:'a Krb_info.t
    -> f:(Context.t -> 'a Krb_result.t)
    -> 'a Or_error.t Deferred.t
end
