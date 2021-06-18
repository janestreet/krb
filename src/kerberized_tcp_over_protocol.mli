open! Core
open! Async
open! Import

(** The following functions are used to reduce code duplication between this
    implementation and lib/krb_for_low_latency_transport. They implement the guts of
    kerberized_tcp.ml abstractly over a [Protocol_with_test_mode]. *)

module Client : sig
  val connect_and_handshake
    :  (module Protocol_with_test_mode.S
         with type protocol_backend = 'backend
          and type Connection.t = 'conn)
    -> create_backend:
         (socket:([ `Active ], Socket.Address.Inet.t) Socket.t
          -> tcp_reader:Reader.t
          -> tcp_writer:Writer.t
          -> 'backend Or_error.t)
    -> ?buffer_age_limit:[ `At_most of Time.Span.t | `Unlimited ]
    -> ?interrupt:unit Deferred.t
    -> ?reader_buffer_size:int
    -> ?writer_buffer_size:int
    -> ?timeout:Time.Span.t
    -> ?time_source:Time_source.t
    -> ?override_supported_versions:int list
    -> ?cred_cache:Cred_cache.t
    -> authorize:Authorize.t
    -> krb_mode:Mode.Client.t
    -> Socket.Address.Inet.t Tcp.Where_to_connect.t
    -> 'conn Deferred.Or_error.t

  (** The clients should be very careful about doing any read/write operation directly on
      the returned socket. For one, reading from the socket in [Priv] or [Safe] mode would
      return encrypted data.

      There are very rare cases when one might want to use the socket instead of the
      connection. *)
  val connect_sock_and_handshake
    :  (module Protocol_with_test_mode.S
         with type protocol_backend = 'backend
          and type Connection.t = 'conn)
    -> create_backend:
         (socket:([ `Active ], Socket.Address.Inet.t) Socket.t -> 'backend Or_error.t)
    -> ?interrupt:unit Deferred.t
    -> ?timeout:Time.Span.t
    -> ?override_supported_versions:int list
    -> ?cred_cache:Cred_cache.t
    -> authorize:Authorize.t
    -> krb_mode:Mode.Client.t
    -> Socket.Address.Inet.t Tcp.Where_to_connect.t
    -> ('conn * ([ `Active ], Socket.Address.Inet.t) Socket.t) Deferred.Or_error.t
end

module Server : sig
  module Endpoint : sig
    val create
      :  Server_key_source.t
      -> (Principal.t
          * (unit
             -> [ `Service of Keytab.t | `User_to_user_via_tgt of Internal.Credentials.t ]
                  Deferred.Or_error.t))
           Deferred.Or_error.t
  end

  val handler_from_server_protocol
    :  ?on_kerberos_error:
      [ `Call of Socket.Address.Inet.t -> exn -> unit | `Ignore | `Raise ]
    -> ?on_handshake_error:
         [ `Call of Socket.Address.Inet.t -> exn -> unit | `Ignore | `Raise ]
    -> ?on_handler_error:
         [ `Call of Socket.Address.Inet.t -> exn -> unit | `Ignore | `Raise ]
    -> (Socket.Address.Inet.t -> 'conn -> unit Deferred.t)
    -> (peer:Socket.Address.Inet.t
        -> 'backend
        -> ( 'conn
           , [ `Handshake_error of Error.t | `Krb_error of Error.t | `Rejected_client ]
           )
             Deferred.Result.t)
    -> Socket.Address.Inet.t
    -> 'backend Or_error.t
    -> unit Deferred.t

  val krb_server_protocol
    :  (module Protocol_with_test_mode_intf.S
         with type protocol_backend = 'backend
          and type Connection.t = 'conn)
    -> authorize:Authorize.t
    -> Mode.Server.t
    -> (peer:Socket.Address.Inet.t
        -> 'backend
        -> ( 'conn
           , [ `Handshake_error of Error.t | `Krb_error of Error.t | `Rejected_client ]
           )
             Deferred.Result.t)
         Deferred.Or_error.t

  val krb_or_anon_server_protocol
    :  (module Protocol_backend_intf.S with type t = 'backend)
    -> (module Protocol_with_test_mode_intf.S
         with type protocol_backend = 'backend
          and type Connection.t = 'conn)
    -> peek_protocol_version_header:
         ('backend
          -> [< `Eof
             | `Not_enough_data
             | `Ok of Protocol_version_header.Known_protocol.t option
             ]
               Deferred.t)
    -> authorize:Authorize.Anon.t
    -> Mode.Server.t
    -> (peer:Socket.Address.Inet.t
        -> 'backend
        -> ( [ `Anon | `Krb of 'conn ]
           , [ `Handshake_error of Error.t | `Krb_error of Error.t | `Rejected_client ]
           )
             Deferred.Result.t)
         Deferred.Or_error.t
end
