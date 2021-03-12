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
      principal (i.e. the bit before "@REALM"). *)
  type t =
    | User of string
    | Service of
        { service : string
        ; hostname : string
        }
  [@@deriving compare, hash, sexp_of]


  (** [to_string] returns either <username> or <service>/<hostname>.

      [of_string] is lenient to inclusion of the realm (for all principals) and full
      qualification of the domain name (for service principals). *)
  include Stringable.S with type t := t

  include Comparator.S with type t := t

  include
    Comparable.S_plain with type t := t with type comparator_witness := comparator_witness

  include Hashable.S_plain with type t := t

  (** accepts <username> or <service>/<hostname> *)
  val arg : t Command.Arg_type.t

  (** Returns [None] if [t] is a [Service] *)
  val to_username : t -> Username.t option

  (** Raises if [t] is a [Service] *)
  val to_username_exn : t -> Username.t

  val service_on_this_host : service:string -> t
end

val create : Name.t -> t Deferred.Or_error.t
val name : t -> Name.t


val to_string : t -> string
val check_password : t -> password:string -> unit Deferred.Or_error.t

(** [kvno] returns the key version number known by the KDC. Consequently this is
    an online test and must be called by a user with a valid TGT. *)
val kvno : ?cred_cache:Internal.Cred_cache.t -> t -> int Deferred.Or_error.t

module Stable : sig
  module Name : sig
    module V1 : sig
      type nonrec t = Name.t =
        | User of string
        | Service of
            { service : string
            ; hostname : string
            }

      include
        Stable_comparable.V1
        with type t := t
        with type comparator_witness = Name.comparator_witness
    end
  end
end

