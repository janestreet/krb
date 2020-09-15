open! Core
open Async

type 'a t =
  { function_ : string
  ; tag_arguments : Sexp.t Lazy.t option
  ; tag_result : ('a -> Sexp.t) option
  ; tag_error : (Krb_error.t -> Sexp.t Deferred.t) option
  }

val create
  :  ?tag_arguments:Sexp.t Lazy.t
  -> ?tag_result:('a -> Sexp.t)
  -> ?tag_error:(Krb_error.t -> Sexp.t Deferred.t)
  -> string
  -> 'a t

val tags : _ t -> Krb_error.t -> Sexp.t option Deferred.t

(** If [Some], contains a suggestion to use a Kerberos sandbox. [None] if we're not in
    tests or already inside a sandbox. *)
val sandbox_tag : Sexp.t option
