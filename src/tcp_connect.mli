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
