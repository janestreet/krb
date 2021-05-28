open! Core
open! Async

(**
   A ['principal t] is used for authorizing a kerberized connection and allows
   checking that the peer is who we expect it to be.

   It gets passed the ip and principal of the peer and decides whether to accept
   the connection or to reject and close the connection.

   Furthermore, any error will propagate to the initiator as part of the connection
   establishment protocol.  This allows the initiator to get a more meaningful message
   (eg. "server rejected client principal or address" instead of something like
   "connection closed").

   Similar functionality can be implemented on the server side by validating the
   [Principal.Name.t] either returned by [Krb.Tcp.connect] or supplied to
   [initial_connection_state] in [Krb.Rpc.serve]/[Krb.Rpc.serve_with_anon]. However if
   [authorize] returns [`Reject] the client will be rejected early, without fully
   establishing a connection.
*)

type t

val create : (Socket.Address.Inet.t -> Principal.Name.t -> [ `Accept | `Reject ]) -> t

(**
   The following helper functions should aid in the common case of validating
   the client or server principals.
*)

val accept_all : t
val accept_single : Principal.Name.t -> t
val accept_multiple : Principal.Name.Set.t -> t

module Anon : sig
  type t

  val create
    :  (Socket.Address.Inet.t -> Principal.Name.t option -> [ `Accept | `Reject ])
    -> t

  (**
     Authorization applied only to kerberized connections. Unkerberized
     connections are accepted without any checks.
  *)

  val accept_all : t
  val accept_single : Principal.Name.t -> t
  val accept_multiple : Principal.Name.Set.t -> t
end

val anon_of_krb : ?on_anon:[ `Accept | `Reject ] (** Default accept *) -> t -> Anon.t
val krb_of_anon : Anon.t -> t

module For_internal_use : sig
  val authorize : t -> Socket.Address.Inet.t -> Principal.Name.t -> [ `Accept | `Reject ]

  module Anon : sig
    val authorize
      :  Anon.t
      -> Socket.Address.Inet.t
      -> Principal.Name.t option
      -> [ `Accept | `Reject ]
  end
end
