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

val create_async
  :  (Socket.Address.Inet.t -> Principal.Name.t -> [ `Accept | `Reject ] Deferred.t)
  -> t

(**
   The following helper functions should aid in the common case of validating
   the client or server principals.
*)

val accept_all : t
val accept_single : Principal.Name.t -> t
val accept_multiple : Principal.Name.Set.t -> t

module Cross_realm : sig
  val create
    :  (Socket.Address.Inet.t -> Cross_realm_principal_name.t -> [ `Accept | `Reject ])
    -> t

  val accept_single : Cross_realm_principal_name.t -> t
  val accept_multiple : Cross_realm_principal_name.Set.t -> t
end

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

val krb_of_anon : Anon.t -> t
val authorization_method : t -> [ `Accept_all | `Custom ]

module For_internal_use : sig
  val authorize
    :  t
    -> Socket.Address.Inet.t
    -> Cross_realm_principal_name.t
    -> [ `Accept | `Reject ] Deferred.t

  val allows_cross_realm : t -> bool

  module Anon : sig
    val authorize
      :  Anon.t
      -> Socket.Address.Inet.t
      -> Principal.Name.t option
      -> [ `Accept | `Reject ] Deferred.t
  end
end
