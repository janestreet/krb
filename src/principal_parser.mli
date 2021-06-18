open! Core

module Result : sig
  type t =
    { primary : string
    ; instance : string option
    ; realm : string option
    }
end

val parse : string -> Result.t
val chop_default_domain : string -> string
