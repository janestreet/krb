open! Core
open! Async


(** A kerberized reader writer pair wraps up an underlying reader writer pair with
    additional logic according to the [Conn_type.t] with which it is created:

    {ul
    {li [Priv]: encrypt writes and decrypt reads. This provides confidentiality and
    integrity.}

    {li [Safe]: add keyed cryptographic checksums to writes and validate them on
    reads. This provides integrity.}

    {li [Auth]: no additional logic.}
    }

    These transformations are done to chunks of bytes at some reasonable granularity.

    All exceptions will be sent to the underlying writer's monitor.

    In the [Auth] case, the underlying reader and writer are the same as the kerberized
    ones.
*)
type t

val plaintext_reader : t -> Reader.t
val plaintext_writer : t -> Writer.t
val writer_closed_and_flushed : t -> unit Deferred.t
val create : Async_protocol.Connection.t -> t Deferred.t
