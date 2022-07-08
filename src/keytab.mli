open! Core
open! Async
open Import

(** A keytab (key table) is a file containing pairs of kerberos principals and encryption
    keys. You can use a keytab file to do kerberos authentication without having to enter
    a password (the key is derived from your password). Keytab's are generally used for 2
    reasons:

    {ol
    {li Kerberized servers *SHOULD* have a keytab so they can accept encrypted data from
    clients, unless they are running as human users}

    {li Kerberized clients *MAY* use a keytab to obtain initial credentials (tgt). This
    might be useful for a long running application, so you don't need to type in a
    password to refresh credentials.}}


    For a more complete explanation, see the MIT krb5 documentation:
    http://web.mit.edu/kerberos/krb5-latest/doc/basic/keytab_def.html
*)

type t = Internal.Keytab.t

module Path : sig
  type t =
    | User (** ${USER}.keytab in [Config.user_keytab_dir] *)
    | Host (** [Config.host_keytab_path] *)
    | File of string
  [@@deriving compare, hash, sexp_of]

  (** The keytab path for the currently running user *)
  val filename : t -> string

  (** [user_keytab user] gets the filename for [user]'s keytab. *)
  val user_keytab : user:string -> string

  val anon : t Command.Anons.t
  val flag : t Command.Param.t
  val optional_flag : t option Command.Param.t
end

val load : Path.t -> t Deferred.Or_error.t

(** Ensure the keytab can be loaded successfully and contains an entry for the given
    principal. This does not verify whether the keytab is up to date, since it only
    performs offline checks. *)
val validate : t -> Principal.t -> unit Deferred.Or_error.t

(** Like [validate] but takes a path and principal name *)
val validate_path : Path.t -> Principal.Name.t -> unit Deferred.Or_error.t

val entries_by_kvno : t -> Internal.Keytab_entry.t list Int.Map.t Deferred.Or_error.t

val entries_for_principal
  :  t
  -> Principal.t
  -> Internal.Keytab_entry.t list Deferred.Or_error.t

val add_spn : t -> Principal.Name.t -> unit Deferred.Or_error.t
val remove_spn : t -> Principal.Name.t -> unit Deferred.Or_error.t

val add_entry
  :  t
  -> password:string
  -> enctype:Internal.Enctype.t
  -> kvno:int
  -> principal:Principal.t
  -> unit Deferred.Or_error.t

(** For each principal and enctype in the keytab, add a fresh key generated from the
    provided password.
    - There must not be principals with conflicting keys with the latest kvno.
    - If no kvno is provided, uses value one greater than the latest kvno found in the
      keytab. *)
val add_new_entry_for_all_principals
  :  ?kvno:int
  -> t
  -> password:string
  -> unit Deferred.Or_error.t

module Stable : sig
  module Path : sig
    module V1 : Stable_without_comparator with type t = Path.t
  end
end
