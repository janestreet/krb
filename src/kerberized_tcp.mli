open! Core
open Async
open Import

type 'a with_krb_args =
  ?cred_cache:Cred_cache.t
  (** This defaults to [Cred_cache.default] for a [TGT] key source and a new MEMORY cache
      for a [Keytab] key source. *)
  -> authorize:Authorize.t (** See the [Authorize] module for more docs *)
  -> krb_mode:Mode.Client.t
  -> 'a

type 'a with_connect_args =
  (Socket.Address.Inet.t Tcp.Where_to_connect.t -> 'a) with_krb_args
    Tcp.Aliases.with_connect_options

val connect : (Kerberized_rw.t * Server_principal.t) Deferred.Or_error.t with_connect_args

val with_connection
  : ((Kerberized_rw.t -> Server_principal.t -> 'a Deferred.t) -> 'a Deferred.Or_error.t)
      with_connect_args

(** Arguments passed through to [Tcp.Server.create].  See [Async.Tcp] for documentation *)
type 'a async_tcp_server_args =
  ?max_connections:int
  -> ?backlog:int
  -> ?drop_incoming_connections:bool
  -> ?buffer_age_limit:Writer.buffer_age_limit
  -> 'a

module Server : sig
  type ('a, 'b) t = ('a, 'b) Tcp.Server.t



  (** Create a TCP server. Unlike an un-kerberized TCP server, this will read and write
      some bytes from/to the underlying socket before returning a [t]. *)
  val create
    : (?on_kerberos_error:
        [ `Call of Socket.Address.Inet.t -> exn -> unit | `Ignore | `Raise ]
       (** [on_kerberos_error] gets called for some kerberos related errors that occur
           during setup of a connection. This includes failure to de/encrypt messages
           during the setup phase, invalid service tickets sent by the client, etc. It
           defaults to logging via [Log.Global.error]. *)
       -> ?on_handshake_error:
         [ `Call of Handshake_error.Kind.t -> Socket.Address.Inet.t -> exn -> unit
         | `Ignore
         | `Raise
         ]
       (** [on_handshake_error] gets called for any non-kerberos related errors that occur
           during setup of a connection. This includes connectivity errors and version
           negotiation errors (which includes kerberos mode mismatch between client and
           server).

           It defaults to [`Ignore].

           Be careful alerting loudly about those errors or choosing [`Raise]. For
           example, [on_handshake_error] may be called if the client crashes when
           connecting to your server. And you probably don't want the server to raise an
           oculus issue or send an eye message when someone kills the commander.
           It may also be triggered by network gremlins: https://wiki/x/34H1Bw.
       *)
       -> ?on_handler_error:
         [ `Call of Socket.Address.Inet.t -> exn -> unit | `Ignore | `Raise ]
       (** [on_handler_error] gets called for any errors that occur within the handler
           function passed into [Server.create]. This includes any exceptions raised by the
           handler function as well as errors in de/encrypting messages. It defaults to
           [`Raise]. *)
       -> ?override_supported_versions:int list
       (** [override_supported_versions] overrides the versions the server
           advertises and accepts. This should only be used in a testing context,
           otherwise krb version negotiation might yield a weird result. *)
       -> authorize:Authorize.t (** See the [Authorize] module for more docs *)
       -> krb_mode:Mode.Server.t
       -> Tcp.Where_to_listen.inet
       -> (Client_principal.t
           -> Socket.Address.Inet.t
           -> Reader.t
           -> Writer.t
           -> unit Deferred.t)
       -> (Socket.Address.Inet.t, int) t Deferred.Or_error.t)
        async_tcp_server_args
end

module Internal : sig
  val connect
    : (?override_supported_versions:int list
       -> ?cred_cache:Cred_cache.t
       -> authorize:Authorize.t
       -> krb_mode:Mode.Client.t
       -> Socket.Address.Inet.t Tcp.Where_to_connect.t
       -> Async_protocol.Connection.t Deferred.Or_error.t)
        Tcp.Aliases.with_connect_options

  module Endpoint : sig
    val create
      :  Server_key_source.t
      -> (Principal.t
          * (unit
             -> [ `Service of Keytab.t | `User_to_user_via_tgt of Internal.Credentials.t ]
                  Deferred.Or_error.t))
           Deferred.Or_error.t
  end

  module Server : sig
    type 'connection handle_client :=
      Socket.Address.Inet.t -> 'connection -> unit Deferred.t

    type ('authorize, 'r) krb_args :=
      ?on_kerberos_error:
        [ `Call of Socket.Address.Inet.t -> exn -> unit | `Ignore | `Raise ]
      -> ?on_handshake_error:
           [ `Call of Handshake_error.Kind.t -> Socket.Address.Inet.t -> exn -> unit
           | `Ignore
           | `Raise
           ]
      -> ?on_handler_error:
           [ `Call of Socket.Address.Inet.t -> exn -> unit | `Ignore | `Raise ]
      -> ?override_supported_versions:int list
      -> authorize:'authorize
      -> krb_mode:Mode.Server.t
      -> 'r

    type ('authorize, 'connection) serve :=
      ( 'authorize
      , Tcp.Where_to_listen.inet
      -> 'connection handle_client
      -> (Socket.Address.Inet.t, int) Server.t Deferred.Or_error.t )
        krb_args
        async_tcp_server_args

    type ('authorize, 'connection) create_handler :=
      ( 'authorize
      , 'connection handle_client
      -> (Socket.Address.Inet.t -> Reader.t -> Writer.t -> unit Deferred.t)
           Deferred.Or_error.t )
        krb_args

    (** [additional_magic_numbers] adds additional magic numbers to be
        advertised by the server during protocol negotiation, usually in
        the context of reporting metadata about the server. If
        [override_supported_versions] is also specified, these numbers are
        still going to be advertised.

        These two arguments are ignored when using [Test_with_principal] as Krb mode. *)

    val create_handler
      :  ?additional_magic_numbers:int list
      -> (Authorize.t, Async_protocol.Connection.t) create_handler

    val create
      :  ?additional_magic_numbers:int list
      -> (Authorize.t, Async_protocol.Connection.t) serve

    module Krb_or_anon_conn : sig
      type t =
        | Krb of Async_protocol.Connection.t
        | Anon of (Reader.t * Writer.t)
    end

    (** This is a bit misleading because it doesn't work with an unkerberized tcp client.
        It is in an [Internal] module because it is useful for implementing kerberized rpc
        [create_handler_with_anon].

        The [create_handler_with_anon] server peeks the first few bytes to check if the
        client is sending a kerberos protocol header. If the unkerberized tcp client is
        expecting the server to send some initial bytes, it will be waiting until
        something presumably times out because the server is waiting for the client to
        send bytes also. *)
    val create_handler_with_anon : (Authorize.Anon.t, Krb_or_anon_conn.t) create_handler

    (** Similar to [create_handler_with_anon], but creates a tcp server, rather than just
        the client handler. *)
    val create_with_anon : (Authorize.Anon.t, Krb_or_anon_conn.t) serve
  end
end
