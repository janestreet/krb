open! Core
open! Async

(** A helper function to [Tcp.connect] and then call [handshake]. *)
val connect_and_handshake
  : (Socket.Address.Inet.t Tcp.Where_to_connect.t
     -> handshake:
          (socket:([ `Active ], Socket.Address.Inet.t) Socket.t
           -> tcp_reader:Reader.t
           -> tcp_writer:Writer.t
           -> 'conn Deferred.Or_error.t)
     -> 'conn Deferred.Or_error.t)
      Tcp.with_connect_options

(** A helper function to [Tcp.connect_sock] and then call [handshake]. This one doesn't
    create a reader and writer like the one above. *)
val connect_sock_and_handshake
  :  ?interrupt:unit Deferred.t
  -> ?timeout:Time.Span.t
  -> ?time_source:[> read ] Time_source.T1.t
  -> Socket.Address.Inet.t Tcp.Where_to_connect.t
  -> handshake:
       (socket:([ `Active ], Socket.Address.Inet.t) Socket.t -> 'conn Deferred.Or_error.t)
  -> ('conn * ([ `Active ], Socket.Address.Inet.t) Socket.t) Deferred.Or_error.t
