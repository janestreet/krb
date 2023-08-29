open! Core

(** supported encryption algorithms *)
type t [@@deriving sexp_of]

include Comparable.S with type t := t
include Stringable.S with type t := t

(** AES-128 CTS mode with 96-bit SHA-1 HMAC *)
val aes128_cts_hmac_sha1_96 : t

(** AES-256 CTS mode with 96-bit SHA-1 HMAC *)
val aes256_cts_hmac_sha1_96 : t

(** RC4 with HMAC *)
val arcfour_hmac : t

(** [of_int] raises if the encyption type is not one of the supported types above *)
val of_int : int -> t

val to_int : t -> int
val arg : t Command.Arg_type.t

(** The set of encryption types we should be putting in keytabs. Most useful for passing
    to [Krb.Keytab.add_new_entry_for_all_principals]. *)
val current_for_keytabs : Set.t

module Stable : sig
  module V1 : Stable with type t = t
end
