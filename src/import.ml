(* most users of this library should ignore [Internal] things mentioned in the
   interface. *)
module Time = Time_float_unix
module Internal = Krb_internal_public.Std
module Config = Internal.Config
module Username = Username_kernel.Username
