open! Core
open! Async

type t =
  { client_principal : Principal.Name.t (** The client principal *)
  ; cross_realm_client_principal : Cross_realm_principal_name.t
  (** The client principal with realm information *)
  ; request_forwarded_creds : unit -> Cred_cache.t Deferred.Or_error.t
  (** Request a forwarded TGT from the client. The client must have explicitly enabled
      credential forwarding with [on_credential_forwarding_request] on connection
      establishment. *)
  }
[@@deriving fields ~getters ~iterators:create, sexp_of]
