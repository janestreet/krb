open Core
open Async
open Import

type query = unit [@@deriving bin_io]
type response = Internal.Auth_context.Krb_cred.t Or_error.t [@@deriving bin_io]

let rpc =
  Rpc.Rpc.create
    ~name:"krb_request_forwarded_credentials"
    ~version:1
    ~bin_query
    ~bin_response
;;
