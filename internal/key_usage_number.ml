open! Core

type t = int [@@deriving sexp_of]

let to_int = Fn.id

(* See https://tools.ietf.org/html/rfc4120#section-7.5.1 and /usr/include/krb5/krb5.h *)

let as_req_pa_enc_ts = 1
let kdc_rep_ticket = 2
let as_rep_encpart = 3
let tgs_req_ad_sesskey = 4
let tgs_req_ad_subkey = 5
let tgs_req_auth_cksum = 6
let tgs_req_auth = 7
let tgs_rep_encpart_sesskey = 8
let tgs_rep_encpart_subkey = 9
let ap_req_auth_cksum = 10
let ap_req_auth = 11
let ap_rep_encpart = 12
let krb_priv_encpart = 13
let krb_cred_encpart = 14
let krb_safe_cksum = 15
let app_data_encrypt = 16
let app_data_cksum = 17
let krb_error_cksum = 18
let ad_kdcissued_cksum = 19
let ad_mte = 20
let ad_ite = 21
