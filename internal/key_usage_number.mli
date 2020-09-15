open! Core

(** Key usage numbers. *)
type t [@@deriving sexp_of]

val to_int : t -> int

(** Constructors *)

val as_req_pa_enc_ts : t
val kdc_rep_ticket : t
val as_rep_encpart : t
val tgs_req_ad_sesskey : t
val tgs_req_ad_subkey : t
val tgs_req_auth_cksum : t
val tgs_req_auth : t
val tgs_rep_encpart_sesskey : t
val tgs_rep_encpart_subkey : t
val ap_req_auth_cksum : t
val ap_req_auth : t
val ap_rep_encpart : t
val krb_priv_encpart : t
val krb_cred_encpart : t
val krb_safe_cksum : t
val app_data_encrypt : t
val app_data_cksum : t
val krb_error_cksum : t
val ad_kdcissued_cksum : t
val ad_mte : t
val ad_ite : t
