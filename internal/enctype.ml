(* The list of all kerberos encryption types is found in krb5.hin

   Of those, we only support

   #define ENCTYPE_AES128_CTS_HMAC_SHA1_96 0x0011 /**< RFC 3962 */
   #define ENCTYPE_AES256_CTS_HMAC_SHA1_96 0x0012 /**< RFC 3962 */
   #define ENCTYPE_ARCFOUR_HMAC            0x0017
*)

module Stable = struct
  open! Core.Core_stable

  module V1 = struct
    module T = struct
      type t =
        | KRB5_ENCTYPE_AES128_CTS_HMAC_SHA1_96
        | KRB5_ENCTYPE_AES256_CTS_HMAC_SHA1_96
        | KRB5_ENCTYPE_ARCFOUR_HMAC
      [@@deriving bin_io, compare, sexp]
    end

    include T
    include Comparator.V1.Make (T)
  end
end

open Core

module Raw = struct
  external of_string : string -> int Krb_result.t = "caml_krb5_string_to_enctype"
end

module C = struct
  type t = Stable.V1.t =
    | KRB5_ENCTYPE_AES128_CTS_HMAC_SHA1_96
    | KRB5_ENCTYPE_AES256_CTS_HMAC_SHA1_96
    | KRB5_ENCTYPE_ARCFOUR_HMAC
  [@@deriving compare, enumerate, sexp_of]

  type comparator_witness = Stable.V1.comparator_witness

  let comparator = Stable.V1.comparator

  let of_int = function
    | 17 -> KRB5_ENCTYPE_AES128_CTS_HMAC_SHA1_96
    | 18 -> KRB5_ENCTYPE_AES256_CTS_HMAC_SHA1_96
    | 23 -> KRB5_ENCTYPE_ARCFOUR_HMAC
    | i -> failwithf "Invalid or unsupported krb5 enctype. %i" i ()
  ;;

  let to_int = function
    | KRB5_ENCTYPE_AES128_CTS_HMAC_SHA1_96 -> 17
    | KRB5_ENCTYPE_AES256_CTS_HMAC_SHA1_96 -> 18
    | KRB5_ENCTYPE_ARCFOUR_HMAC -> 23
  ;;

  let of_string s =
    Raw.of_string s
    |> Krb_result.to_or_error ~info:"[krb5_string_to_enctype]"
    |> Result.map ~f:of_int
    |> ok_exn
  ;;

  let to_string = function
    | KRB5_ENCTYPE_AES128_CTS_HMAC_SHA1_96 -> "aes128-cts-hmac-sha1-96"
    | KRB5_ENCTYPE_AES256_CTS_HMAC_SHA1_96 -> "aes256-cts-hmac-sha1-96"
    | KRB5_ENCTYPE_ARCFOUR_HMAC -> "arcfour-hmac"
  ;;

  let%test_unit _ =
    List.iter all ~f:(fun t ->
      [%test_result: string]
        (to_string t)
        ~expect:
          (sexp_of_t t
           |> Sexp.to_string
           |> String.lowercase
           |> String.tr ~target:'_' ~replacement:'-'
           |> String.chop_prefix_exn ~prefix:"krb5-enctype-"))
  ;;

  let%test_unit _ =
    List.iter all ~f:(fun t ->
      let t' = of_string (to_string t) in
      [%test_result: t] ~expect:t t')
  ;;

  let sexp_of_t t = String.sexp_of_t (to_string t)
  let t_of_sexp s = of_string (String.t_of_sexp s)
end

include C
include Comparable.Make_using_comparator (C)

let aes128_cts_hmac_sha1_96 = KRB5_ENCTYPE_AES128_CTS_HMAC_SHA1_96
let aes256_cts_hmac_sha1_96 = KRB5_ENCTYPE_AES256_CTS_HMAC_SHA1_96
let arcfour_hmac = KRB5_ENCTYPE_ARCFOUR_HMAC

let arg =
  Command.Arg_type.of_alist_exn
    ~list_values_in_help:false
    (List.map all ~f:(fun t -> to_string t, t))
;;
