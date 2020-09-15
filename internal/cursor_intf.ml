open! Core
open Async

module type Arg = sig
  module Container : sig
    type raw
    type t

    val tag : t -> Sexp.t
    val to_raw : t -> raw
  end

  module Item : sig
    type raw
    type t

    val of_raw : raw -> t Deferred.Or_error.t
    val free : Context.t -> raw -> unit
  end

  module Cursor : sig
    type t

    val start : Context.t -> Container.raw -> t Krb_result.t
    val advance : Context.t -> Container.raw -> t -> Item.raw option Krb_result.t
    val finish : Context.t -> Container.raw -> t -> unit Krb_result.t
  end

  val info : string
end

module type Cursor = sig
  module type Arg = Arg

  module Make (S : Arg) : sig
    val get_all : S.Container.t -> S.Item.t list Deferred.Or_error.t
  end
end
