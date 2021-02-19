open! Core

type t =
  | Deny
  | Allow_server_to_impersonate_me of { forwardable_tkt : bool }
