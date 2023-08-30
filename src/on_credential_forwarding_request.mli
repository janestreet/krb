open! Core

type t =
  | Deny (** Don't forward credentials. *)
  | Allow_server_to_impersonate_me of { forwardable_tkt : bool }
      (** The client credentials are sent to the server to be used to carry out actions on
      your behalf. This allows the server to impersonate you, thus use this only
      if you know what you are doing and it is strictly necessary.
      [forwardable_tkt] determines whether the forwarded ticket is
      forwardable again.*)
