open! Core
open! Async

(** An instantiation of [Persistent_connection] for creating persistent kerberized rpc and
    versioned_rpc connections *)

(** Arguments passed through to [Persistent_connection.Rpc.create].
    See [Persistent_connection] for documentation. *)
type ('a, 'event) persistent_connection_args :=
  server_name:string
  -> ?log:Log.t
  -> ?on_event:('event -> unit Deferred.t)
  -> ?retry_delay:(unit -> Time_float.Span.t)
  -> 'a

type ('event, 't, 'state) create :=
  ( (?krb_mode:Mode.Client.t
     -> ?bind_to_address:Unix.Inet_addr.t
     -> ?implementations:
       (Server_principal.t -> 'state Rpc.Connection.Client_implementations.t)
     -> ?description:Info.t
     -> ?cred_cache:Cred_cache.t
     -> authorize:Authorize.t
     -> (unit -> Host_and_port.t Deferred.Or_error.t)
     -> 't)
      Kerberized_rpc.async_rpc_args
  , 'event )
    persistent_connection_args

(** Arguments passed through to [Persistent_connection.Rpc.create].
    See [Persistent_connection] for documentation. *)

module Versioned_rpc : sig
  include Persistent_connection.S with type conn = Versioned_rpc.Connection_with_menu.t

  val create' : (Host_and_port.t Event.t, t, 'a) create
end

module Rpc : sig
  include Persistent_connection.S with type conn = Rpc.Connection.t

  val create' : (Host_and_port.t Event.t, t, 'a) create
end
