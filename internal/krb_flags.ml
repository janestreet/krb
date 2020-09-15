open! Core

module Ap_req = struct
  type t =
    | AP_OPTS_USE_SESSION_KEY
    | AP_OPTS_MUTUAL_REQUIRED
end

module Auth_context = struct
  type t =
    | KRB5_AUTH_CONTEXT_DO_TIME
    | KRB5_AUTH_CONTEXT_RET_TIME
    | KRB5_AUTH_CONTEXT_DO_SEQUENCE
    | KRB5_AUTH_CONTEXT_RET_SEQUENCE
end

module Get_credentials = struct
  type t =
    | KRB5_GC_CACHED
    | KRB5_GC_USER_USER
    | KRB5_GC_NO_STORE
  [@@deriving equal]
end
