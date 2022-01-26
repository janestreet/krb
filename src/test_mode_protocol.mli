include Test_mode_protocol_intf.Test_mode_protocol

module Syn : sig
  type t [@@deriving bin_io]
end

module Ack : sig
  type t [@@deriving bin_io]
end
