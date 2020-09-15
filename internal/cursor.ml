open Core
open Async

module type Arg = Cursor_intf.Arg

module Make (S : Arg) = struct
  let get_all container =
    let tag_arguments = lazy (S.Container.tag container) in
    let container_raw = S.Container.to_raw container in
    let info = Krb_info.create ~tag_arguments S.info in
    Context_sequencer.enqueue_job_with_info ~info ~f:(fun c ->
      let open Result.Let_syntax in
      let%bind cursor = S.Cursor.start c container_raw in
      let rec gather acc =
        match%bind S.Cursor.advance c container_raw cursor with
        | Some item ->
          Context_sequencer.add_finalizer item ~f:S.Item.free;
          gather (item :: acc)
        | None -> return (List.rev acc)
      in
      let result = gather [] in
      let%bind () = S.Cursor.finish c container_raw cursor in
      result)
    >>=? Deferred.Or_error.List.map ~f:S.Item.of_raw
  ;;
end
