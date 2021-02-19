open Core
open Async
open Import

type query = unit [@@deriving bin_io]
type response = Internal.Auth_context.Krb_cred.t Or_error.t [@@deriving bin_io]

val rpc : (query, response) Rpc.Rpc.t
