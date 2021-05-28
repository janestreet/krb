(** This module is a wrapper around the RPC library which

    {ol
    {li Ensures all connections use Kerberos authentication (with optional encryption or
    integrity checking)}

    {li Provides the RPC server/client with the identity of the client/server in a
    reliable manner.}

    {li Attempts to make switching over from the [Async.Rpc] relatively painless.}
    }

    This module also reserves the right to take the following liberties:

    {ol
    {li A certain amount of duplication with the RPC library is allowed, as previous
    attempts to reduce duplication caused great harm to the code quality of said library.}

    {li To offset said duplication, this module may choose not to implement all features
    present in the Async RPC library and instead present a simplified interface. We can
    always add such functionality later as the need presents itself.}
    }
*)

open! Core
open! Async
module Transport = Kerberized_rpc_transport

(** Arguments passed through to underlying [Async.Rpc] connection functions.
    See [Async.Rpc] for documentation *)
type 'a async_rpc_args =
  ?max_message_size:int
  -> ?handshake_timeout:Time.Span.t
  -> ?heartbeat_config:Rpc.Connection.Heartbeat_config.t
  -> 'a

module Connection : sig
  type t = Rpc.Connection.t

  type ('client_identity, 'authorize, 'conn_state, 'r) krb_rpc_args :=
    ?on_kerberos_error:
      [ `Call of Socket.Address.Inet.t -> exn -> unit | `Ignore | `Raise ]
    (** [on_kerberos_error] defaults to logging to [Log.Global.error]. See
        [kerberized_tcp.mli] for more details. *)
    -> ?on_handshake_error:
         [ `Call of Socket.Address.Inet.t -> exn -> unit | `Ignore | `Raise ]
    (** on_handshake_error defaults to [`Ignore] *)
    -> ?on_done_with_internal_buffer:[ `Do_nothing | `Zero ]
    (** [on_done_with_internal_buffer] determines if internal buffers are zeroed out after
        use. The default is [`Do_nothing]. *)
    -> authorize:'authorize (** See the [Authorize] module for more docs *)
    -> implementations:'conn_state Rpc.Implementations.t
    -> initial_connection_state:
         ('client_identity -> Socket.Address.Inet.t -> t -> 'conn_state)
    -> 'r

  type ('client_identity, 'authorize, 'conn_state) server_args :=
    ( 'client_identity
    , 'authorize
    , 'conn_state
    , where_to_listen:Tcp.Where_to_listen.inet
    -> krb_mode:Mode.Server.t
    -> unit
    -> (Socket.Address.Inet.t, int) Kerberized_tcp.Server.t Deferred.Or_error.t )
      krb_rpc_args
      Kerberized_tcp.async_tcp_server_args
      async_rpc_args

  (** [serve] starts an RPC server that provides the given [implementations] *)
  val serve : (Client_identity.t, Authorize.t, 'a) server_args

  (** [serve_with_anon] starts an RPC server that allows connections from both [Krb.Rpc]
      and [Async.Rpc] clients

      NOTE: [serve_with_anon] is provided to ease the transition from unkerberized
      applications to kerberized ones.  After upgrading all servers and clients to use
      [Krb.Rpc] rather than [Async.Rpc], nearly all apps should switch their servers from
      [serve_with_anon] to [serve].

      This will fail to recognize sufficiently old kerberized RPC clients, so changing
      from [serve] to [serve_with_anon] can introduce problems, but such a change should
      rarely be necessary, if ever.
  *)
  val serve_with_anon : (Client_identity.t option, Authorize.Anon.t, 'a) server_args

  (** [create_handler] is the same as [serve], but it provides a handler that can be used
      with an externally created TCP server. *)
  val create_handler
    : ( Client_identity.t
      , Authorize.t
      , 'conn_state
      , Mode.Server.t
        -> (Socket.Address.Inet.t -> Reader.t -> Writer.t -> unit Deferred.t)
             Deferred.Or_error.t )
        krb_rpc_args
        async_rpc_args

  type ('a, 'conn_state) with_client_args :=
    (?implementations:
      (Server_principal.t -> 'conn_state Rpc.Connection.Client_implementations.t)
     -> ?description:Info.t
     -> ?cred_cache:Cred_cache.t (** This defaults to a new MEMORY cache. *)
     -> ?buffer_age_limit:[ `At_most of Time.Span.t | `Unlimited ]
     (** Uses the default value in [Writer.create] if not passed. *)
     -> ?on_credential_forwarding_request:
       (Server_principal.t -> On_credential_forwarding_request.t)
     (** [on_credential_forwarding_request] is called to validate a credential request
         from a server. The default is [Fn.const `Deny].

         NOTE: Applications that want to use delegated credentials are sitting in a
         trusted spot, and if compromised, could be used to hijack the credentials of
         anyone accessing the service. As a result, we do not allow people to set up such
         applications without vetting and careful considerations around security
         first. *)
     -> ?on_done_with_internal_buffer:[ `Do_nothing | `Zero ]
     (** [on_done_with_internal_buffer] determines if internal buffers are zeroed out after
         use. The default is [`Do_nothing]. *)
     -> ?krb_mode:Mode.Client.t (** default: [Mode.Client.kerberized] *)
     -> authorize:Authorize.t (** See the [Authorize] module for more docs *)
     -> Socket.Address.Inet.t Tcp.Where_to_connect.t
     -> 'a)
      async_rpc_args

  (** [client] creates a [Connection.t] appropriate for dispatching RPC's to a
      kerberized server. *)
  val client : (t Deferred.Or_error.t, _) with_client_args

  val with_client : ((t -> 'a Deferred.t) -> 'a Deferred.Or_error.t, _) with_client_args

  (** Only used for internal testing of the library *)
  module Internal : sig
    val client
      :  ?override_supported_versions:int list
      -> (t Deferred.Or_error.t, _) with_client_args
  end
end
