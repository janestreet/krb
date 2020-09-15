open! Core
include Config_gen_intf

module Shared = struct
  type t =
    { realm : string option [@sexp.option]
    ; host_keytab_path : string option [@sexp.option]
    ; user_keytab_dir_template : string option [@sexp.option]
    ; domain_name : string option option [@sexp.option]
    ; debug_log_config : Debug_log_config.Stable.V1.t option [@sexp.option]
    ; verbose_errors : bool option [@sexp.option]
    ; am_sandboxed : bool option [@sexp.option]
    }
  [@@deriving fields, sexp]

  let environment_variable = "OCAML_KRB_CONFIG"
  let username_template = "%{username}"
end

include Shared

module type S = S with type t = t

let make ~default ~help_message =
  (module struct
    include Shared

    let field_descriptions () =
      let field to_sexp description ac field =
        let sexp =
          Option.value_map
            ~default:(Sexp.Atom "<unspecified>")
            (Field.get field default)
            ~f:to_sexp
        in
        (Field.name field, sexp, description) :: ac
      in
      let fields =
        Fields.fold
          ~init:[]
          ~realm:
            (field
               [%sexp_of: string]
               [ "\n\
                 \  The realm to attach to principals constructed with \
                  [Krb.Principal.Name].\n\
                 \  This should usually be a capitalized version of [domain_name].\n"
               ])
          ~host_keytab_path:
            (field
               [%sexp_of: string]
               [ "\n  The path of a keytab specified by [Keytab.Path.Host].\n" ])
          ~user_keytab_dir_template:
            (field
               [%sexp_of: string]
               [ sprintf
                   "\n\
                   \  The path of a keytab specified by [Keytab.Path.User] is determined \
                    by\n\
                   \  [filled in user_keytab_dir_template]/$USER.keytab.\n\
                   \  This must be an absolute path with the substring %s, which will be\n\
                   \  be filled in with the currently running user.\n"
                   username_template
               ])
          ~domain_name:
            (field
               [%sexp_of: string option]
               [ "\n  The domain name of hosts in this realm.\n" ])
          ~debug_log_config:
            (field
               [%sexp_of: Debug_log_config.Stable.V1.t]
               [ sprintf
                   "\n\
                   \  Print library debugging information to the outputs specified. The \
                    following\n\
                   \  are some example configs:\n\
                   \  %s\n\
                   \ "
                   (List.map
                      Debug_log_config.examples
                      ~f:Debug_log_config.Stable.V1.sexp_of_t
                    |> List.map ~f:Sexp.to_string
                    |> String.concat ~sep:"\n  ")
               ])
          ~verbose_errors:
            (field [%sexp_of: bool] [ "\n  Whether error messages should be verbose.\n" ])
          (* Purposefully undocumented; this should only be set by the kerberos sandbox. *)
          ~am_sandboxed:(fun acc _ -> acc)
      in
      String.concat
        (List.map
           (List.sort fields ~compare:(fun (name1, _, _) (name2, _, _) ->
              String.compare name1 name2))
           ~f:(fun (name, default, description) ->
             String.concat
               ("\n"
                :: name
                :: " (default "
                :: Sexp.to_string default
                :: ")"
                :: description)))
    ;;

    let help_message () =
      let field_descriptions = field_descriptions () in
      help_message ~default ~environment_variable ~field_descriptions
    ;;

    let usage () =
      eprintf "%s%!" (help_message ());
      exit 1
    ;;

    let t =
      match Sys.getenv environment_variable with
      | None -> default
      | Some "" -> usage ()
      | Some string ->
        (match Result.try_with (fun () -> t_of_sexp (Sexp.of_string string)) with
         | Ok t -> t
         | Error exn ->
           eprintf
             "%s\n\n"
             (Sexp.to_string_hum
                (Error.sexp_of_t
                   (Error.create
                      (sprintf
                         "invalid value for %s environment variable"
                         environment_variable)
                      exn
                      [%sexp_of: exn])));
           usage ())
    ;;

    let get_with_default field =
      match Option.first_some (Field.get field t) (Field.get field default) with
      | None ->
        failwithf
          "The Kerberos configuration is missing a required field (%s).\n\
           Pass the environment variable as described or modify the Config module.\n\n\
           ===============================================================\n\n\
           %s"
          (Field.name field)
          (help_message ())
          ()
      | Some value -> value
    ;;

    let validate_user_keytab_dir_template x =
      let template_occurences =
        List.length
          (String.substr_index_all x ~may_overlap:false ~pattern:username_template)
      in
      if not (template_occurences = 1 && Filename.is_absolute x)
      then
        failwithf
          "[user_keytab_dir_template] must be an absolute path with the template %s"
          username_template
          ()
    ;;

    let realm = get_with_default Fields.realm
    let host_keytab_path = get_with_default Fields.host_keytab_path

    let user_keytab_dir_template =
      let x = get_with_default Fields.user_keytab_dir_template in
      validate_user_keytab_dir_template x;
      x
    ;;

    let user_keytab_dir ~username =
      String.substr_replace_all
        user_keytab_dir_template
        ~pattern:username_template
        ~with_:username
    ;;

    let domain_name = get_with_default Fields.domain_name
    let debug_log_config = get_with_default Fields.debug_log_config
    let verbose_errors = get_with_default Fields.verbose_errors
    let am_sandboxed = get_with_default Fields.am_sandboxed
    let print_debug_messages = List.length debug_log_config > 0

    let t =
      { realm = Some realm
      ; host_keytab_path = Some host_keytab_path
      ; user_keytab_dir_template = Some user_keytab_dir_template
      ; domain_name = Some domain_name
      ; debug_log_config = Some debug_log_config
      ; verbose_errors = Some verbose_errors
      ; am_sandboxed = Some am_sandboxed
      }
    ;;
  end : S)
;;
