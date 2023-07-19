open! Core
open Async
open Import


(** A principal is a unique identity to which kerberos can assign tickets. Generally,
    principals are a name (containing an arbitrary number of components
    separated by '/') followed by "@<REALM>".  The [Krb] library allows for two
    kinds of principals:

    User:        <username>@<REALM>
    Service:     <service>/<hostname>.<domain>@<REALM>



    See [Config] for information on how to configure <REALM> and <domain>.

    For a more complete explanation, see the MIT krb5 documentation:
    http://web.mit.edu/kerberos/krb5-1.5/krb5-1.5.4/doc/krb5-user/What-is-a-Kerberos-Principal_003f.html
*)
type t = Internal.Principal.t

module Name : sig
  (** A [Name.t] represents the conventional names that may appear in a Kerberos
      principal (i.e. the bit before "@REALM").

      By default, when constructing a principal from this type, we assume that the
      principal is within the default realm configured in [krb.conf]. If realm
      information should be preserved (eg. within cross-realm environments), use
      [Cross_realm_principal_name.t] instead.
  *)
  type t =
    | User of string
    | Service of
        { service : string
        ; hostname : string
        }
  [@@deriving compare, hash, sexp_of]


  (** [to_string] returns either <username> or <service>/<hostname>.

      [of_string] is lenient to inclusion of the realm (for all principals) and full
      qualification of the domain name (for service principals). We drop the provided
      realm and drop a provided domain name if it matches the default domain. *)

  include Stringable.S with type t := t
  include Comparable.S_plain with type t := t
  include Hashable.S_plain with type t := t

  (** accepts <username> or <service>/<hostname> *)
  val arg : t Command.Arg_type.t

  (** Returns [None] if [t] is a [Service] *)
  val to_username : t -> Username.t option

  (** Raises if [t] is a [Service] *)
  val to_username_exn : t -> Username.t

  val service_on_this_host : service:string -> t

  (** Cross-realm *)

  val of_cross_realm : Cross_realm_principal_name.t -> t
  val with_realm : realm:Realm.t -> t -> Cross_realm_principal_name.t
  val with_default_realm : t -> Cross_realm_principal_name.t Deferred.Or_error.t
end

val create : Name.t -> t Deferred.Or_error.t
val name : t -> Name.t

(** Constructs a principal [<service_name>/<canonicalized_hostname>], where the
    canonicalized hostname is derived from [hostname] with the rules defined by the
    Kerberos config (as described at
    https://web.mit.edu/kerberos/krb5-devel/doc/admin/princ_dns.html). *)
val service_with_canonicalized_hostname
  :  service:string
  -> hostname:string
  -> t Deferred.Or_error.t

module Cross_realm : sig
  val create : Cross_realm_principal_name.t -> t Deferred.Or_error.t
  val name : t -> Cross_realm_principal_name.t
end


val to_string : t -> string
val check_password : t -> password:string -> unit Deferred.Or_error.t

(** [kvno] returns the key version number known by the KDC. Consequently this is
    an online test and must be called by a user with a valid TGT. *)
val kvno : ?cred_cache:Internal.Cred_cache.t -> t -> int Deferred.Or_error.t

module Stable : sig
  module Name : sig
    module V1 : sig
      type t = Name.t [@@deriving bin_io, compare, sexp, stable_witness]

      include
        Comparable.Stable.V1.With_stable_witness.S
        with type comparable := Name.t
        with type comparator_witness = Name.comparator_witness
    end
  end
end

