open! Core

module type S = sig
  include Protocol_intf.S

  module Test_mode :
    Test_mode_protocol.S
    with type protocol_backend = protocol_backend
     and type Connection.t = Connection.t
end

module type Protocol_with_test_mode = sig
  module type S = S
end
