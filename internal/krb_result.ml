open! Core

type 'a t = ('a, Krb_error.t) Result.t

let to_or_error ?context ~info result =
  Result.map_error result ~f:(fun code ->
    let krb_error = Krb_error.to_string code ?context ~info in
    Error.create_s [%message "" ~_:(krb_error : string) (code : int32)])
;;
