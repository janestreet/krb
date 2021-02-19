open! Core
open! Async
open! Import

(** The following functions are used to reduce code duplication between this
    implementation and lib/krb_for_low_latency_transport. They implement the guts of
    kerberized_rpc.ml abstractly over a [Protocol.Connection]. *)

val handle_client
  :  (module Protocol.Connection with type t = 'conn)
  -> ?heartbeat_config:Rpc.Connection.Heartbeat_config.t
  -> ?handshake_timeout:Time.Span.t
  -> (Client_identity.t -> Socket.Address.Inet.t -> Rpc.Connection.t -> 'a)
  -> 'a Rpc.Implementations.t
  -> (Socket.Address.Inet.t -> Rpc.Transport.t -> 'conn -> unit Deferred.t) Staged.t

val handle_client_with_anon
  :  (module Protocol.Connection with type t = 'conn)
  -> ?heartbeat_config:Rpc.Connection.Heartbeat_config.t
  -> ?handshake_timeout:Time.Span.t
  -> (Client_identity.t option -> Socket.Address.Inet.t -> Rpc.Connection.t -> 'a)
  -> 'a Rpc.Implementations.t
  -> (Socket.Address.Inet.t -> Rpc.Transport.t -> 'conn option -> unit Deferred.t)
       Staged.t

val client
  :  (module Protocol.Connection with type t = 'conn)
  -> ?heartbeat_config:Rpc.Connection.Heartbeat_config.t
  -> ?implementations:(Server_principal.t -> 'a Rpc.Connection.Client_implementations.t)
  -> ?description:Info.t
  -> ?on_credential_forwarding_request:
       (Server_principal.t -> On_credential_forwarding_request.t)
  -> finish_handshake_by:Time.t
  -> Tcp.Where_to_connect.inet
  -> Rpc.Transport.t
  -> 'conn
  -> Rpc.Connection.t Deferred.Or_error.t

module For_testing : sig
  type 'mode serve :=
    implementations:Principal.Name.t Rpc.Implementations.t
    -> initial_connection_state:
         (Client_identity.t
          -> Socket.Address.Inet.t
          -> Rpc.Connection.t
          -> Principal.Name.t)
    -> where_to_listen:Tcp.Where_to_listen.inet
    -> krb_mode:'mode Mode.mode
    -> Tcp.Server.inet Deferred.Or_error.t

  type 'mode with_client :=
    on_connection:(Socket.Address.Inet.t -> Server_principal.t -> [ `Accept | `Reject ])
    -> krb_mode:'mode Mode.mode
    -> Tcp.Where_to_connect.inet
    -> (Rpc.Connection.t -> unit Deferred.t)
    -> unit Deferred.Or_error.t

  val ensure_test_mode_works : serve:_ serve -> with_client:_ with_client -> unit
end
