open! Core
open! Async
include Protocol.Make (Protocol_backend_async)

module Connection = struct
  include Connection

  let reader t = Protocol_backend_async.reader (backend t)
  let writer t = Protocol_backend_async.writer (backend t)
end

module Test_mode = Test_mode_protocol.Make (Protocol_backend_async)
