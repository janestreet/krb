open Base
open Stdio
module Configurator = Configurator.V1

let () =
  Configurator.main ~name:"krb" (fun configurator ->
    let { Configurator.Pkg_config.libs; cflags } =
      configurator
      |> Configurator.Pkg_config.get
      |> Option.map ~f:(fun pkg_config ->
           Configurator.Pkg_config.query pkg_config ~package:"krb5")
      |> Option.join
      |> Option.value ~default:{ Configurator.Pkg_config.libs = []; cflags = [] }
    in
    let files = [ "libs", libs; "cflags", cflags ] in
    List.iter files ~f:(fun (name, values) ->
      let filename = Printf.sprintf "krb5-%s.sexp" name in
      let data = Sexp.to_string [%sexp (values : string list)] in
      Out_channel.write_all filename ~data))
;;
