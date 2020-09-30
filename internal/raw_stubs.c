#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <krb5/krb5.h>
#include <netinet/in.h>
#include <errno.h>

#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/custom.h>
#include <caml/bigarray.h>
#include <caml/fail.h>
#include <caml/threads.h>
#include "ocaml_utils.h"

/* Documentation for the krb5 API is available here: http://web.mit.edu/kerberos

   The below bindings were originally based off:
   http://web.mit.edu/kerberos/krb5-1.14/doc/index.html

   The documentation is sometimes pretty lacking; nothing beats looking at the source
   code.
*/


/*
 *
 * Utility functions
 *
 */

/* taken from the OCaml source. Internally, OCamls [type inet_addr] is just a pointer
   to Linux' [inet_addr_t] = [uint32_t]. So all this does is cast out the type */
#define GET_INET_ADDR(v) ((struct in_addr *) (v))

#define Val_ec(x) caml_copy_int32((x))

/* Outputs a ('a, krb5_error_code) Core.Result.t */
static CAMLprim value
wrap_result(value v_data, krb5_error_code const error)
{
  CAMLparam1(v_data);
  tag_t tag = 0;
  CAMLlocal2(o_result, o_res_val);

  if(error == 0)
  {
    tag = 0;
    o_res_val = v_data;
  }
  else
  {
    tag = 1;
    o_res_val = Val_ec(error);
  }

  o_result = caml_alloc_small(1, tag);
  Field(o_result, 0) = o_res_val;

  CAMLreturn(o_result);
}

/*
 * No fancy type handling for now.
 */
static struct custom_operations krb_default_ops = {
  "com.janestreet.caml.krb",
  custom_finalize_default,
  custom_compare_default,
  custom_hash_default,
  custom_serialize_default,
  custom_deserialize_default,
  custom_compare_default,
#ifdef custom_fixed_length_default
  custom_fixed_length_default,
#endif
};

/* Use a token for the context so we don't forget to sequence calls that use the
   krb5_context type */
#define SECRET_TOKEN 42

/*
 * global singleton krb5_context
 */
krb5_context the_context_INTERNAL = NULL;
value ocaml_context_token = Val_int(SECRET_TOKEN);

CAMLprim value
caml_krb5_init_context_global() {
  CAMLparam0();
  krb5_error_code retval;

  if(the_context_INTERNAL) {
    CAMLreturn(wrap_result(ocaml_context_token, 0));
  }

  caml_release_runtime_system();
  retval = krb5_init_context(&the_context_INTERNAL);
  caml_acquire_runtime_system();

  /* This is not actually needed because [ocaml_context_token] is an int, but it
     is included for overall c stub style (and adherence with ocaml documentation). */
  caml_register_generational_global_root(&ocaml_context_token);

  CAMLreturn(wrap_result(ocaml_context_token, retval));
}

static krb5_context the_context(value v_context_token) {
  CAMLparam1(v_context_token);

  assert(Int_val(v_context_token) == SECRET_TOKEN);

  CAMLreturnT(krb5_context, the_context_INTERNAL);
}

/*
 * Hopefully most of the dirty work of creating wrappers is handled here.
 * field val contains the krb5_ type val.
 */
#define create_wrap(name)                                \
  CAMLprim value create_ ## name() {                     \
    CAMLparam0();                                        \
    CAMLlocal1(x);                                       \
    x = caml_alloc_custom(&krb_default_ops,              \
        sizeof(struct wrap_ ## name), 0, 1);             \
    memset(((struct wrap_ ## name *)Data_custom_val(x)), \
	   0, sizeof(struct wrap_ ## name));                   \
    CAMLreturn(x);                                       \
  }


#define make_wrap(name)                                  \
  struct wrap_ ## name {                                 \
    name val;                                            \
  };                                                     \
  create_wrap(name)

#define make_ptr_wrap(name)                              \
  struct wrap_ ## name {                                 \
    name *val;                                           \
  };                                                     \
  create_wrap(name)

/*
 *
 * Access stuff in the wrappers
 *
 */
#define get_custom(name, v) ((struct wrap_ ## name *)Data_custom_val(v))
#define get_val(name, v) (get_custom(name, v)->val)
#define set_val(name, v, new_val) (get_custom(name, (v)))->val = (new_val)

/*
 * Create Kerberos type wrappers.  We end up with structs and
 * functions called create_krb5_<the-type>(void).  Semi-colons here
 * makes strict compiler flags unhappy. We explicitly don't add finalizers
 * here because we must be careful to sequence all calls that use the
 * global [krb5_context].
 */
make_wrap(krb5_context)
make_wrap(krb5_principal)
make_wrap(krb5_ccache)
make_wrap(krb5_auth_context)
make_wrap(krb5_keytab)
make_wrap(krb5_kt_cursor)
make_wrap(krb5_cc_cursor)
make_wrap(krb5_creds)
make_wrap(krb5_data)
make_wrap(krb5_enc_data)
make_ptr_wrap(krb5_error)
make_ptr_wrap(krb5_ticket)
make_ptr_wrap(krb5_keytab_entry)
make_ptr_wrap(krb5_keyblock)
make_ptr_wrap(krb5_get_init_creds_opt)

/*
 *
 * Utility functions
 *
 */

/* Copy an ocaml string to a c string. The length of the c string will be the
   length of the ocaml string up to the first null byte. */
static char * str_dup(value v_str)
{
  CAMLparam1(v_str);
  CAMLreturnT(char*, strndup(String_val(v_str), caml_string_length(v_str)));
}

/* Copy the entire contents of an ocaml string (which may include null bytes) to
   a char buffer. */
static char * data_dup(value v_str)
{
  CAMLparam1(v_str);

  char *data = (char*)malloc(caml_string_length(v_str));
  memcpy(data, String_val(v_str), caml_string_length(v_str));

  CAMLreturnT(char*, data);
}

/*
 *
 * Kerberos-ish primitives
 *
 */

CAMLprim value
caml_krb5_auth_con_init(value v_context_token)
{
  CAMLparam1(v_context_token);
  CAMLlocal1(o_auth_context);

  krb5_context context = the_context(v_context_token);
  krb5_error_code retval;
  krb5_auth_context auth_context = NULL;

  caml_release_runtime_system();
  retval = krb5_auth_con_init(context, &auth_context);
  caml_acquire_runtime_system();

  o_auth_context = create_krb5_auth_context();
  set_val(krb5_auth_context, o_auth_context, auth_context);

  CAMLreturn(wrap_result(o_auth_context, retval));
}


CAMLprim value
caml_krb5_auth_con_free(value v_context_token, value v_auth_context)
{
  CAMLparam2(v_context_token, v_auth_context);

  krb5_context context = the_context(v_context_token);
  krb5_auth_context auth_context = get_val(krb5_auth_context, v_auth_context);

  krb5_auth_con_free(context, auth_context);

  CAMLreturn(Val_unit);
}

CAMLprim value
caml_krb5_free_cred_contents(value v_context_token, value v_creds)
{
  CAMLparam2(v_context_token, v_creds);

  krb5_context context = the_context(v_context_token);
  krb5_creds temp_creds = get_val(krb5_creds, v_creds);

  krb5_free_cred_contents(context, &temp_creds);

  CAMLreturn(Val_unit);
}

CAMLprim value
caml_krb5_parse_name(value v_context_token, value v_name)
{
  CAMLparam2(v_context_token, v_name);
  CAMLlocal1(o_princ);

  krb5_context context = the_context(v_context_token);
  krb5_error_code retval;
  krb5_principal princ = NULL;
  const char *name = String_val(v_name);

  retval = krb5_parse_name(context, name, &princ);

  if(retval)
    CAMLreturn(wrap_result(Val_unit, retval));
  else
  {
    o_princ = create_krb5_principal();
    set_val(krb5_principal, o_princ, princ);
    CAMLreturn(wrap_result(o_princ, retval));
  }
}

CAMLprim value
caml_krb5_unparse_name(value v_context_token, value v_principal)
{
  CAMLparam2(v_context_token, v_principal);
  CAMLlocal1(s);

  krb5_context context = the_context(v_context_token);
  krb5_error_code retval;
  char *string = NULL;
  krb5_principal principal = get_val(krb5_principal, v_principal);

  retval = krb5_unparse_name(context, principal, &string);

  if(retval)
    CAMLreturn(wrap_result(Val_unit, retval));
  else
  {
    s = caml_copy_string(string);
    krb5_free_unparsed_name(context, string);
    CAMLreturn(wrap_result(s, retval));
  }
}

CAMLprim value
caml_krb5_kt_close(value v_context_token, value v_keytab)
{
  CAMLparam2(v_context_token, v_keytab);

  krb5_context context = the_context(v_context_token);
  krb5_keytab keytab = get_val(krb5_keytab, v_keytab);

  caml_release_runtime_system();
  krb5_kt_close(context, keytab);
  caml_acquire_runtime_system();

  CAMLreturn(Val_unit);
}

CAMLprim value
caml_krb5_kt_resolve(value v_context_token, value v_keytab_name)
{
  CAMLparam2(v_context_token, v_keytab_name);
  CAMLlocal1(o_keytab);

  krb5_context context = the_context(v_context_token);
  krb5_error_code retval;
  krb5_keytab keytab = NULL;
  char *keytab_name = str_dup(v_keytab_name);

  caml_release_runtime_system();
  retval = krb5_kt_resolve(context, keytab_name, &keytab);
  caml_acquire_runtime_system();

  free(keytab_name);

  o_keytab = create_krb5_keytab();
  set_val(krb5_keytab, o_keytab, keytab);

  CAMLreturn(wrap_result(o_keytab, retval));
}

CAMLprim value
caml_krb5_free_principal(value v_context_token, value v_principal)
{
  CAMLparam2(v_context_token, v_principal);

  krb5_context context = the_context(v_context_token);
  krb5_principal principal = get_val(krb5_principal, v_principal);

  krb5_free_principal(context, principal);

  CAMLreturn(Val_unit);
}

/* Outputs a (bigsubstring, krb5_error_code) Core.Result.t */
static CAMLprim value handle_outbuffer(krb5_data *data, krb5_error_code const error)
{
  CAMLparam0();
  CAMLlocal2(result, res_val);

  if(error == 0)
  {
    long length = data->length;
    result = caml_alloc(1, 0);
    /* The flag [CAML_BA_MANAGED] is important here. This tells the
       OCaml runtime that it "owns" the memory at [data->data] and
       tells the built-in finalizer for [Bigarray.t] to free that
       memory upon collection.

       Note: this means we needn't call [krb5_free_data_contents] for freeing
       [struct krb5_data *data]. [krb5_free_data_contents] just calls
       [free(data->data)]. The finalizer takes care of this. */
    res_val = caml_ba_alloc(
        CAML_BA_CHAR | CAML_BA_C_LAYOUT | CAML_BA_MANAGED,
        1, data->data, &length);
  }
  else
  {
    result = caml_alloc(1, 1);
    res_val = Val_ec(error);
  }

  Store_field(result, 0, res_val);

  CAMLreturn(result);
}

/* because Bigstrings/Bigarray's/Bigsubstrings are allocated with malloc,
 * I don't have to worry about them being moved by the OCaml garbage
 * collector when I release the runtime system */
static krb5_data data_of_bigsubstring(value v_bigsubstring)
{
  CAMLparam1(v_bigsubstring);
  CAMLlocal1(v_input_data);

  krb5_data ret;
  int in_pos, in_len;

  v_input_data = Field(v_bigsubstring, 0);
  in_pos = Int_val(Field(v_bigsubstring, 1));
  in_len = Int_val(Field(v_bigsubstring, 2));

  ret.data = (char*)Caml_ba_data_val(v_input_data) + in_pos;
  ret.length = in_len;
  /* This is poorly commented, but I believe this field is only used in
  debugging as a tag indicating what type of struct this is (it always shows up
  as the first field, so you can find it without knowing what it is). The point
  is, it shouldn't matter what we put here since we aren't using krb5 debugging
  tools. */
  ret.magic = 0;

  CAMLreturnT(krb5_data, ret);
}

static krb5_data data_of_bigstring(value v_bigstring)
{
  CAMLparam1(v_bigstring);
  CAMLlocal1(v_input_data);

  krb5_data ret;

  ret.data = (char*)Caml_ba_data_val(v_bigstring);
  ret.length = Caml_ba_array_val(v_bigstring)->dim[0];
  ret.magic = 0;

  CAMLreturnT(krb5_data, ret);
}

CAMLprim value
caml_krb5_mk_req_native(value v_context_token, value v_auth_context,
    value v_req_flags, value v_servicename, value v_hostname,
    value v_ccache)
{
  CAMLparam5(v_context_token, v_auth_context, v_req_flags, v_servicename, v_hostname);
  CAMLxparam1(v_ccache);

  krb5_context context = the_context(v_context_token);
  krb5_error_code err;
  krb5_data outbuf;
  krb5_flags flags = 0;
  krb5_auth_context auth_context = get_val(krb5_auth_context, v_auth_context);
  krb5_ccache ccache = get_val(krb5_ccache, v_ccache);
  char *hostname = str_dup(v_hostname);
  char *service = str_dup(v_servicename);

  while(v_req_flags != Val_int(0))
  {
    switch(Int_val(Field(v_req_flags, 0)))
    {
      case 0: flags |= AP_OPTS_USE_SESSION_KEY; break;
      case 1: flags |= AP_OPTS_MUTUAL_REQUIRED; break;
      default: caml_invalid_argument(
                   "caml_krb5_mk_req_native: invalid krb5_mk_req_flag");
    };

    v_req_flags = Field(v_req_flags, 1);
  }

  caml_release_runtime_system();
  err = krb5_mk_req(
        context,
        &auth_context,
        flags,
        service,
        hostname,
        NULL,
        ccache,
        &outbuf);
  caml_acquire_runtime_system();

  free(hostname);
  free(service);

  CAMLreturn(handle_outbuffer(&outbuf, err));
}

CAMLprim value
caml_krb5_mk_req_bytecode(value *a, int const argn)
{
  (void)argn;
  return caml_krb5_mk_req_native(a[0], a[1], a[2], a[3], a[4], a[5]);
}

CAMLprim value
caml_krb5_rd_req(value v_context_token, value v_auth_context,
    value v_input, value v_principal, value v_keytab_opt)
{
  CAMLparam5(v_context_token, v_auth_context, v_input, v_principal, v_keytab_opt);
  CAMLlocal2(o_princ, v_keytab);

  krb5_context context = the_context(v_context_token);
  krb5_auth_context auth_context = get_val(krb5_auth_context, v_auth_context);
  krb5_principal principal = get_val(krb5_principal, v_principal);
  krb5_keytab keytab;
  krb5_principal out_principal;

  krb5_error_code err;
  krb5_data inputbuf = data_of_bigstring(v_input);
  krb5_ticket *ticket = NULL;

  if(Is_block(v_keytab_opt)) {
    v_keytab = Field(v_keytab_opt, 0);

    keytab = get_val(krb5_keytab, v_keytab);
  } else {
    keytab = NULL;
  }

  caml_release_runtime_system();
  err = krb5_rd_req(
      context,
      &auth_context,
      &inputbuf,
      principal,
      keytab,
      NULL,
      &ticket);
  caml_acquire_runtime_system();

  if(err) {
    CAMLreturn(wrap_result(Val_unit, err));
  }

  err = krb5_copy_principal(context,
                            ticket->enc_part2->client,
                            &out_principal);

  if(err) {
    CAMLreturn(wrap_result(Val_unit, err));
  }

  o_princ = create_krb5_principal();
  set_val(krb5_principal, o_princ, out_principal);
  krb5_free_ticket(context, ticket);

  CAMLreturn(wrap_result(o_princ, err));
}

CAMLprim value
caml_krb5_mk_rep(value v_context_token, value v_auth_context)
{
  CAMLparam2(v_context_token, v_auth_context);

  krb5_context context = the_context(v_context_token);
  krb5_auth_context auth_context = get_val(krb5_auth_context, v_auth_context);
  krb5_data outbuf;
  krb5_error_code err;

  caml_release_runtime_system();
  err = krb5_mk_rep(context, auth_context, &outbuf);
  caml_acquire_runtime_system();

  CAMLreturn(handle_outbuffer(&outbuf, err));
}

CAMLprim value
caml_krb5_rd_rep(value v_context_token, value v_auth_context, value v_input)
{
  CAMLparam3(v_context_token, v_auth_context, v_input);

  krb5_context context = the_context(v_context_token);
  krb5_auth_context auth_context = get_val(krb5_auth_context, v_auth_context);
  krb5_data inputbuf = data_of_bigstring(v_input);
  krb5_error_code err;
  krb5_ap_rep_enc_part *repl;

  caml_release_runtime_system();
  err = krb5_rd_rep(context, auth_context, &inputbuf, &repl);
  caml_acquire_runtime_system();

  krb5_free_ap_rep_enc_part(context, repl);

  CAMLreturn(wrap_result(Val_unit, err));
}

CAMLprim value
caml_krb5_auth_con_setflags(value v_context_token, value v_auth_context, value v_flags)
{
  CAMLparam3(v_context_token, v_auth_context, v_flags);

  krb5_context context = the_context(v_context_token);
  krb5_int32 flags = 0;
  krb5_auth_context auth_context = get_val(krb5_auth_context, v_auth_context);

  while(v_flags != Val_int(0))
  {
    switch(Int_val(Field(v_flags, 0)))
    {
      case 0: flags |= KRB5_AUTH_CONTEXT_DO_TIME; break;
      case 1: flags |= KRB5_AUTH_CONTEXT_RET_TIME; break;
      case 2: flags |= KRB5_AUTH_CONTEXT_DO_SEQUENCE; break;
      case 3: flags |= KRB5_AUTH_CONTEXT_RET_SEQUENCE; break;
      default: caml_invalid_argument("caml_krb5_mk_con_setflags: invalid krb5_auth_context_flag");
    }

    v_flags = Field(v_flags, 1);
  }

  krb5_auth_con_setflags(context, auth_context, flags);

  CAMLreturn(Val_unit);
}

CAMLprim value
caml_krb5_auth_con_setaddrs_compat(value v_context_token, value v_auth_context,
                                   value v_local_port, value v_remote_port)
{
  CAMLparam4(v_context_token, v_auth_context, v_local_port, v_remote_port);
  krb5_auth_context auth_context = get_val(krb5_auth_context, v_auth_context);

  krb5_address local_addr;
  krb5_address remote_addr;
  krb5_error_code err;

  /* unsigned short is the type of sockaddr_in.sin_port */
  unsigned short local_port = htons(Int_val(v_local_port));
  unsigned short remote_port = htons(Int_val(v_remote_port));

  local_addr.addrtype = ADDRTYPE_IPPORT;
  local_addr.length = sizeof(local_port);
  local_addr.contents = (krb5_octet*)&local_port;

  remote_addr.addrtype = ADDRTYPE_IPPORT;
  remote_addr.length = sizeof(remote_port);
  remote_addr.contents = (krb5_octet*)&remote_port;

  err = krb5_auth_con_setaddrs(
        the_context(v_context_token), auth_context,
        &local_addr, &remote_addr);

  CAMLreturn(wrap_result(Val_unit, err));
}

/* [caml_krb5_auth_con_setaddrs] sets IPv4 local&remote addrs&ports in krb auth_context.
 * It is compatible with what [krb5_auth_con_genaddrs] [0,1] does, but takes addrs as
 * arguments, instead of fetching them from the socket file descriptor.
 *
 * [0] (with all KRB5_AUTH_CONTEXT_GENERATE_{LOCAL,REMOTE}{,_FULL}_ADDR)
 * [1] https://github.com/krb5/krb5/blob/master/src/lib/krb5/os/genaddrs.c#L65
 * */
CAMLprim value
caml_krb5_auth_con_setaddrs(value v_context_token, value v_auth_context,
                                   value v_local_port, value v_remote_port,
                                   value v_local_addr, value v_remote_addr)
{
  CAMLparam5(v_context_token, v_auth_context, v_local_port, v_remote_port, v_local_addr);
  CAMLxparam1(v_remote_addr);
  krb5_auth_context auth_context = get_val(krb5_auth_context, v_auth_context);

  struct in_addr local_addr;
  struct in_addr remote_addr;
  krb5_address krb_local_addr;
  krb5_address krb_remote_addr;
  krb5_address krb_local_port;
  krb5_address krb_remote_port;
  krb5_error_code err;

  /* unsigned short is the type of sockaddr_in.sin_port */
  unsigned short local_port = htons(Int_val(v_local_port));
  unsigned short remote_port = htons(Int_val(v_remote_port));

  /* convert back int32 from [core_unix_inet4_addr_to_int32_exn] */
  local_addr.s_addr = ntohl(Int32_val(v_local_addr));
  remote_addr.s_addr = ntohl(Int32_val(v_remote_addr));

  krb_local_port.addrtype = ADDRTYPE_IPPORT;
  krb_local_port.length = sizeof(local_port);
  krb_local_port.contents = (krb5_octet*)&local_port;

  krb_remote_port.addrtype = ADDRTYPE_IPPORT;
  krb_remote_port.length = sizeof(remote_port);
  krb_remote_port.contents = (krb5_octet*)&remote_port;

  krb_local_addr.addrtype = ADDRTYPE_INET;
  krb_local_addr.length = sizeof(local_addr);
  krb_local_addr.contents = (krb5_octet*)&local_addr;

  krb_remote_addr.addrtype = ADDRTYPE_INET;
  krb_remote_addr.length = sizeof(remote_addr);
  krb_remote_addr.contents = (krb5_octet*)&remote_addr;

  err = krb5_auth_con_setaddrs(
        the_context(v_context_token), auth_context,
        &krb_local_addr, &krb_remote_addr);

  if(err != 0) {
    CAMLreturn(wrap_result(Val_unit, err));
  }

  err = krb5_auth_con_setports(
        the_context(v_context_token), auth_context,
        &krb_local_port, &krb_remote_port);

  CAMLreturn(wrap_result(Val_unit, err));
}

CAMLprim value caml_krb5_auth_con_setaddrs_bytecode(value * argv, int argn) {
  assert(argn == 6);
  return caml_krb5_auth_con_setaddrs(
      argv[0], argv[1], argv[2], argv[3], argv[4], argv[5]);
}

typedef krb5_error_code
(*priv_msg_func)(
    krb5_context,
    krb5_auth_context,
    krb5_data const*,
    krb5_data*,
    krb5_replay_data*);

static CAMLprim value
krb5_msg_func(value v_context_token, value v_auth_context, value v_in, priv_msg_func msg_func)
{
  CAMLparam3(v_context_token, v_auth_context, v_in);

  krb5_context context = the_context(v_context_token);
  krb5_auth_context auth_context = get_val(krb5_auth_context, v_auth_context);
  krb5_error_code err;
  krb5_data inputbuf, outbuf;

  inputbuf = data_of_bigsubstring(v_in);

  caml_release_runtime_system();
  err = msg_func(
      context,
      auth_context,
      &inputbuf,
      &outbuf, NULL);
  caml_acquire_runtime_system();

  CAMLreturn(handle_outbuffer(&outbuf, err));
}

CAMLprim value
caml_krb5_mk_priv(value v_context_token, value v_auth_context, value v_in)
{ return krb5_msg_func(v_context_token, v_auth_context, v_in, krb5_mk_priv); }

CAMLprim value
caml_krb5_rd_priv(value v_context_token, value v_auth_context, value v_in)
{ return krb5_msg_func(v_context_token, v_auth_context, v_in, krb5_rd_priv); }



CAMLprim value
caml_krb5_c_decrypt_native(value v_context_token, value v_keyblock,
    value v_usage, value v_enc_type, value v_kvno, value v_in)
{
  CAMLparam5(v_context_token, v_keyblock, v_usage, v_enc_type, v_kvno);
  CAMLxparam1(v_in);

  krb5_error_code err;
  krb5_context context = the_context(v_context_token);
  krb5_keyblock* keyblock;
  krb5_keyusage usage;
  krb5_enc_data enc_part;
  krb5_data outbuf;

  keyblock = get_val(krb5_keyblock, v_keyblock);
  usage = Int_val(v_usage);

  enc_part.enctype = Int_val(v_enc_type);
  enc_part.kvno = Int_val(v_kvno);
  enc_part.ciphertext = data_of_bigsubstring(v_in);

  outbuf.length = enc_part.ciphertext.length;

  caml_release_runtime_system();

  if ((outbuf.data = malloc(outbuf.length))) {
    err = krb5_c_decrypt(
        context,
        keyblock,
        usage,
        NULL, /* cipher_state */
        &enc_part,
        &outbuf);
  } else {
    err = ENOMEM;
  }

  caml_acquire_runtime_system();

  CAMLreturn(handle_outbuffer(&outbuf, err));
}

CAMLprim value
caml_krb5_c_decrypt_bytecode(value *a, int const argn)
{
  (void)argn;
  assert(argn == 6);
  return caml_krb5_c_decrypt_native(a[0], a[1], a[2], a[3], a[4], a[5]);
}



CAMLprim value
caml_krb5_mk_safe(value v_context_token, value v_auth_context, value v_in)
{ return krb5_msg_func(v_context_token, v_auth_context, v_in, krb5_mk_safe); }

CAMLprim value
caml_krb5_rd_safe(value v_context_token, value v_auth_context, value v_in)
{ return krb5_msg_func(v_context_token, v_auth_context, v_in, krb5_rd_safe); }

CAMLprim value
caml_krb5_get_error_message(value v_context_token_opt, value v_error_code)
{
  CAMLparam2(v_context_token_opt, v_error_code);
  CAMLlocal1(o_error_message);

  const char *error_message = NULL;
  krb5_error_code error_code = Int32_val(v_error_code);

  krb5_context context = NULL;

  if(Is_block(v_context_token_opt)) {
    context = the_context(Field(v_context_token_opt, 0));
  }

  caml_release_runtime_system();
  error_message = krb5_get_error_message(context, error_code);
  caml_acquire_runtime_system();

  o_error_message = caml_copy_string(error_message);
  krb5_free_error_message(context, error_message);

  CAMLreturn(o_error_message);
}

CAMLprim value
caml_krb5_get_init_creds_opt_alloc(value v_context_token,
                                   value v_tkt_life,
                                   value v_renew_life,
                                   value v_forwardable,
                                   value v_proxiable)
{
  CAMLparam5(v_context_token, v_tkt_life, v_renew_life, v_forwardable, v_proxiable);
  CAMLlocal1(o_opts);
  krb5_context context = the_context(v_context_token);
  int tkt_life = Int_val(v_tkt_life);
  int renew_life = Int_val(v_renew_life);
  int forwardable = Bool_val(v_forwardable);
  int proxiable = Bool_val(v_proxiable);
  krb5_get_init_creds_opt *opts;
  krb5_error_code retval;

  retval = krb5_get_init_creds_opt_alloc(context, &opts);

  if (!retval) {
    krb5_get_init_creds_opt_set_tkt_life (opts, (krb5_deltat)tkt_life);
    krb5_get_init_creds_opt_set_renew_life(opts, (krb5_deltat)renew_life);
    krb5_get_init_creds_opt_set_forwardable (opts, forwardable);
    krb5_get_init_creds_opt_set_proxiable (opts, proxiable);

    o_opts = create_krb5_get_init_creds_opt();
    set_val(krb5_get_init_creds_opt, o_opts, opts);
  }

  CAMLreturn(wrap_result(o_opts, retval));
}

CAMLprim value
caml_krb5_get_init_creds_opt_free(value v_context_token, value v_opts)
{
  CAMLparam2(v_context_token, v_opts);
  krb5_context context = the_context(v_context_token);
  krb5_get_init_creds_opt *opts = get_val(krb5_get_init_creds_opt, v_opts);

  krb5_get_init_creds_opt_free(context, opts);

  CAMLreturn(Val_unit);
}

CAMLprim value
caml_krb5_get_init_creds_password(value v_context_token, value v_tkt_service_opt,
                                  value v_options, value v_client, value v_password)
{
  CAMLparam5(v_context_token, v_tkt_service_opt, v_options, v_client, v_password);
  CAMLlocal1(o_creds);

  krb5_context context = the_context(v_context_token);
  krb5_error_code err;
  krb5_creds creds;
  krb5_get_init_creds_opt *opt = get_val(krb5_get_init_creds_opt, v_options);
  krb5_principal client = get_val(krb5_principal, v_client);
  char *password = str_dup(v_password);
  char *tkt_service = NULL; /* Ticket granting service */

  if(Is_block(v_tkt_service_opt)) {
    tkt_service = str_dup(Field(v_tkt_service_opt, 0));
  }

  caml_release_runtime_system();

  err = krb5_get_init_creds_password(context,
                                     &creds,
                                     client,
                                     password,
                                     NULL, /* Don't need prompter */
                                     NULL, /* Don't need prompter data */
                                     0,    /* Ticket becomes valid now */
                                     tkt_service,
                                     opt);

  caml_acquire_runtime_system();

  free(password);
  free(tkt_service);

  o_creds = create_krb5_creds();
  set_val(krb5_creds, o_creds, creds);

  CAMLreturn(wrap_result(o_creds, err));
}


CAMLprim value
caml_krb5_get_init_creds_keytab(value v_context_token, value v_tkt_service_opt,
                                value v_options, value v_client, value v_keytab)
{
  CAMLparam5(v_context_token, v_tkt_service_opt, v_options, v_client, v_keytab);
  CAMLlocal1(o_creds);

  krb5_context context = the_context(v_context_token);
  krb5_error_code err;
  krb5_creds creds;
  krb5_get_init_creds_opt *opt = get_val(krb5_get_init_creds_opt, v_options);
  krb5_principal client = get_val(krb5_principal, v_client);
  krb5_keytab keytab = get_val(krb5_keytab, v_keytab);
  char *tkt_service = NULL; /* Ticket granting service */

  if(Is_block(v_tkt_service_opt)) {
    tkt_service = str_dup(Field(v_tkt_service_opt, 0));
  }

  caml_release_runtime_system();

  err = krb5_get_init_creds_keytab(context,
                                   &creds,
                                   client,
                                   keytab,
                                   0,    /* Ticket becomes valid now */
                                   tkt_service,
                                   opt);

  caml_acquire_runtime_system();

  free(tkt_service);

  o_creds = create_krb5_creds();
  set_val(krb5_creds, o_creds, creds);

  CAMLreturn(wrap_result(o_creds, err));
}

CAMLprim value
caml_krb5_get_renewed_creds(value v_context_token, value v_client, value v_ccache,
                            value v_tkt_service)
{
  CAMLparam4(v_context_token, v_client, v_ccache, v_tkt_service);
  CAMLlocal1(o_creds);

  krb5_context context = the_context(v_context_token);
  krb5_error_code err;
  krb5_creds creds;
  krb5_principal client = get_val(krb5_principal, v_client);
  krb5_ccache ccache = get_val(krb5_ccache, v_ccache);
  char *tkt_service = str_dup(v_tkt_service);

  caml_release_runtime_system();

  err = krb5_get_renewed_creds(context,
                               &creds,
                               client,
                               ccache,
                               tkt_service);

  caml_acquire_runtime_system();

  free(tkt_service);

  o_creds = create_krb5_creds();
  set_val(krb5_creds, o_creds, creds);

  CAMLreturn(wrap_result(o_creds, err));
}

/* credential cache management stubs */

CAMLprim value
caml_krb5_cc_default(value v_context_token) {
  CAMLparam1(v_context_token);
  CAMLlocal1(o_ccache);

  krb5_context context = the_context(v_context_token);
  krb5_error_code retval;
  krb5_ccache ccache = NULL;

  caml_release_runtime_system();
  retval = krb5_cc_default(context, &ccache);
  caml_acquire_runtime_system();

  o_ccache = create_krb5_ccache();
  set_val(krb5_ccache, o_ccache, ccache);

  CAMLreturn(wrap_result(o_ccache, retval));
}

CAMLprim value
caml_krb5_cc_initialize(value v_context_token, value v_ccache, value v_principal)
{
  CAMLparam3(v_context_token, v_ccache, v_principal);

  krb5_context context = the_context(v_context_token);
  krb5_error_code retval;

  krb5_ccache ccache = get_val(krb5_ccache, v_ccache);
  krb5_principal principal = get_val(krb5_principal, v_principal);

  caml_release_runtime_system();
  retval = krb5_cc_initialize(context, ccache, principal);
  caml_acquire_runtime_system();

  CAMLreturn(wrap_result(Val_unit, retval));
}

CAMLprim value
caml_krb5_cc_get_principal(value v_context_token, value v_ccache) {
  CAMLparam2(v_context_token, v_ccache);
  CAMLlocal1(o_princ);

  krb5_context context = the_context(v_context_token);
  krb5_error_code retval;
  krb5_principal princ = NULL;

  krb5_ccache ccache = get_val(krb5_ccache, v_ccache);

  caml_release_runtime_system();
  retval = krb5_cc_get_principal(context, ccache, &princ);
  caml_acquire_runtime_system();

  o_princ = create_krb5_principal();
  set_val(krb5_principal, o_princ, princ);

  CAMLreturn(wrap_result(o_princ, retval));
}

CAMLprim value
caml_krb5_cc_cache_match(value v_context_token, value v_principal)
{
  CAMLparam2(v_context_token, v_principal);
  CAMLlocal1(o_ccache);

  krb5_context context = the_context(v_context_token);
  krb5_ccache ccache;
  krb5_error_code retval;

  krb5_principal principal = get_val(krb5_principal, v_principal);

  caml_release_runtime_system();
  retval = krb5_cc_cache_match(context, principal, &ccache);
  caml_acquire_runtime_system();

  o_ccache = create_krb5_ccache();
  set_val(krb5_ccache, o_ccache, ccache);

  CAMLreturn(wrap_result(o_ccache, retval));
}

CAMLprim value
caml_krb5_cc_resolve(value v_context_token, value v_path)
{
  CAMLparam2(v_context_token, v_path);
  CAMLlocal1(o_ccache);

  krb5_context context = the_context(v_context_token);
  krb5_ccache ccache;
  krb5_error_code retval;

  char *path = str_dup(v_path);

  caml_release_runtime_system();
  retval = krb5_cc_resolve(context, path, &ccache);
  caml_acquire_runtime_system();

  free(path);

  o_ccache = create_krb5_ccache();
  set_val(krb5_ccache, o_ccache, ccache);

  CAMLreturn(wrap_result(o_ccache, retval));
}

CAMLprim value
caml_krb5_cc_get_type(value v_context_token, value v_ccache)
{
  CAMLparam2(v_context_token, v_ccache);
  CAMLlocal1(o_type);

  krb5_context context = the_context(v_context_token);
  krb5_ccache ccache = get_val(krb5_ccache, v_ccache);
  const char* type;
  int len;

  type = krb5_cc_get_type(context, ccache);
  len = strlen(type);

  o_type = caml_alloc_initialized_string(len, type);

  CAMLreturn(o_type);
}

CAMLprim value
caml_krb5_cc_new_unique(value v_context_token, value v_type)
{
  CAMLparam2(v_context_token, v_type);
  CAMLlocal1(o_ccache);

  krb5_context context = the_context(v_context_token);
  krb5_error_code retval;
  krb5_ccache ccache;
  char *type = str_dup(v_type);

  caml_release_runtime_system();
  /* the docs say the hint argument is unused. */
  retval = krb5_cc_new_unique(context, type, NULL, &ccache);
  caml_acquire_runtime_system();

  free(type);

  o_ccache = create_krb5_ccache();
  set_val(krb5_ccache, o_ccache, ccache);

  CAMLreturn(wrap_result(o_ccache, retval));
}

CAMLprim value
caml_krb5_cc_close(value v_context_token, value v_ccache)
{
  CAMLparam2(v_context_token, v_ccache);

  krb5_context context = the_context(v_context_token);
  krb5_ccache ccache = get_val(krb5_ccache, v_ccache);

  caml_release_runtime_system();
  /* This function can return an error, but we call it as a finalizer. Since the intent is
     to close and discard the credentials cache, there is nothing useful we could do in
     the error case, so we ignore it.
   */
  krb5_cc_close(context, ccache);
  caml_acquire_runtime_system();

  CAMLreturn(Val_unit);
}

CAMLprim value
caml_krb5_cc_get_full_name(value v_context_token, value v_ccache)
{
  CAMLparam2(v_context_token, v_ccache);
  CAMLlocal1(o_fullname_out);

  krb5_context context = the_context(v_context_token);
  char *fullname_out = NULL;
  krb5_error_code retval;

  krb5_ccache ccache = get_val(krb5_ccache, v_ccache);

  caml_release_runtime_system();
  retval = krb5_cc_get_full_name(context, ccache, &fullname_out);
  caml_acquire_runtime_system();

  /* wrap_result will ignore o_fullname_out if retval != 0 so its ok
     for o_fullname_out to be uninitialized. */
  if (retval == 0) {
    o_fullname_out = caml_copy_string(fullname_out);
    krb5_free_string(context, fullname_out);
  }

  CAMLreturn(wrap_result(o_fullname_out, retval));
}

CAMLprim value
caml_krb5_cc_store_cred(value v_context_token, value v_cache, value v_creds)
{
  CAMLparam3(v_context_token, v_cache, v_creds);

  krb5_context context = the_context(v_context_token);
  krb5_error_code retval;

  krb5_ccache cache = get_val(krb5_ccache, v_cache);
  krb5_creds creds = get_val(krb5_creds, v_creds);

  caml_release_runtime_system();
  retval = krb5_cc_store_cred(context, cache, &creds);
  caml_acquire_runtime_system();

  CAMLreturn(wrap_result(Val_unit, retval));
}

CAMLprim value
caml_krb5_cc_start_seq_get(value v_context_token, value v_cache)
{
  CAMLparam2(v_context_token, v_cache);
  CAMLlocal1(o_cursor);

  krb5_context context = the_context(v_context_token);
  krb5_ccache cache;
  krb5_cc_cursor cursor;
  krb5_error_code retval;

  cache = get_val(krb5_ccache, v_cache);

  caml_release_runtime_system();
  retval = krb5_cc_start_seq_get(context, cache, &cursor);
  caml_acquire_runtime_system();

  o_cursor = create_krb5_cc_cursor();
  set_val(krb5_cc_cursor, o_cursor, cursor);

  CAMLreturn(wrap_result(o_cursor, retval));
}

CAMLprim value
caml_krb5_cc_next_cred(value v_context_token, value v_cache, value v_cursor)
{
  CAMLparam3(v_context_token, v_cache, v_cursor);
  CAMLlocal3(o_creds, o_tuple, o_option);

  krb5_context context = the_context(v_context_token);
  krb5_ccache cache;
  krb5_cc_cursor cursor;
  krb5_creds creds;
  krb5_error_code retval;

  cache = get_val(krb5_ccache, v_cache);
  cursor = get_val(krb5_cc_cursor, v_cursor);

  caml_release_runtime_system();
  retval = krb5_cc_next_cred(context, cache, &cursor, &creds);
  caml_acquire_runtime_system();

  if (retval == KRB5_CC_END) {
    CAMLreturn(wrap_result(Val_none, 0));
  }
  else if (retval) {
    CAMLreturn(wrap_result(Val_unit, retval));
  }
  else {
    /* Some credential cache implementations (e.g. FILE) mutate the contents of the cursor
       while others (e.g. MEMORY) mutate the supplied cursor pointer. We make sure to
       update [v_cursor] in case the pointer was changed. */
    set_val(krb5_cc_cursor, v_cursor, cursor);

    o_creds = create_krb5_creds();
    set_val(krb5_creds, o_creds, creds);

    o_option = caml_alloc_some(o_creds);
    CAMLreturn(wrap_result(o_option, retval));
  }
}

CAMLprim value
caml_krb5_cc_end_seq_get(value v_context_token, value v_cache, value v_cursor)
{
  CAMLparam3(v_context_token, v_cache, v_cursor);

  krb5_context context = the_context(v_context_token);
  krb5_ccache cache;
  krb5_cc_cursor cursor;
  krb5_error_code retval;

  cache = get_val(krb5_ccache, v_cache);
  cursor = get_val(krb5_cc_cursor, v_cursor);

  caml_release_runtime_system();
  retval = krb5_cc_end_seq_get(context, cache, &cursor);
  caml_acquire_runtime_system();

  CAMLreturn(wrap_result(Val_unit, retval));
}

CAMLprim value
caml_krb5_string_to_enctype(value v_string)
{
  CAMLparam1(v_string);

  krb5_error_code retval;
  krb5_enctype enctype;
  char *enctypestr = str_dup(v_string);

  caml_release_runtime_system();
  retval = krb5_string_to_enctype(enctypestr, &enctype);
  caml_acquire_runtime_system();

  free(enctypestr);

  CAMLreturn(wrap_result(Val_int(enctype), retval));
}

CAMLprim value
caml_krb5_principal2salt(value v_context_token, value v_principal)
{
  CAMLparam2(v_context_token, v_principal);
  CAMLlocal1(o_salt);

  krb5_context context = the_context(v_context_token);
  krb5_error_code retval;
  krb5_principal principal;
  krb5_data salt;

  principal = get_val(krb5_principal, v_principal);

  caml_release_runtime_system();
  retval = krb5_principal2salt(context, principal, &salt);
  caml_acquire_runtime_system();

  o_salt = create_krb5_data();
  set_val(krb5_data, o_salt, salt);

  CAMLreturn(wrap_result(o_salt, retval));
}

CAMLprim value
caml_krb5_is_config_principal(value v_context_token, value v_principal)
{
  CAMLparam2(v_context_token, v_principal);

  krb5_context context = the_context(v_context_token);
  krb5_principal principal;
  krb5_boolean is_config_principal;

  principal = get_val(krb5_principal, v_principal);

  caml_release_runtime_system();
  is_config_principal = krb5_is_config_principal(context, principal);
  caml_acquire_runtime_system();

  if (is_config_principal == TRUE) {
    CAMLreturn(Val_true);
  } else {
    CAMLreturn(Val_false);
  }
}

CAMLprim value
caml_krb5_free_data_contents(value v_context_token, value v_data)
{
  CAMLparam2(v_context_token, v_data);

  krb5_context context = the_context(v_context_token);
  krb5_data data = get_val(krb5_data, v_data);

  krb5_free_data_contents(context, &data);

  CAMLreturn(Val_unit);
}

CAMLprim value
caml_krb5_create_keyblock_from_key_data(value v_context_token, value v_enctype, value v_keydata) {
  CAMLparam3(v_context_token, v_enctype, v_keydata);
  CAMLlocal1(o_keyblock);

  krb5_context context = the_context(v_context_token);
  krb5_enctype enctype = (krb5_enctype)Int_val(v_enctype);
  krb5_data in_data;
  krb5_error_code retval;
  krb5_keyblock *keyblock = NULL;

  in_data = data_of_bigstring(v_keydata);

  retval = krb5_init_keyblock(context, enctype, in_data.length, &keyblock);
  if (retval) {
    CAMLreturn(wrap_result(Val_unit, retval));
  }

  memcpy(keyblock->contents, in_data.data, in_data.length);

  o_keyblock = create_krb5_keyblock();
  set_val(krb5_keyblock, o_keyblock, keyblock);

  CAMLreturn(wrap_result(o_keyblock, retval));
}

CAMLprim value
caml_krb5_c_string_to_key(value v_context_token, value v_enctype, value v_string, value v_salt)
{
  CAMLparam4(v_context_token, v_enctype, v_string, v_salt);
  CAMLlocal1(o_keyblock);

  krb5_context context = the_context(v_context_token);
  krb5_enctype enctype = (krb5_enctype)Int_val(v_enctype);
  krb5_data in_salt = get_val(krb5_data, v_salt);
  krb5_error_code retval;
  krb5_keyblock *keyblock = NULL;
  krb5_data in_string;

  in_string.length = caml_string_length(v_string);
  in_string.data = data_dup(v_string);

  retval = krb5_init_keyblock(context, enctype, 0, &keyblock);

  if(retval) {
    krb5_free_data_contents(context, &in_string);
    CAMLreturn(wrap_result(Val_unit, retval));
  }

  caml_release_runtime_system();
  retval = krb5_c_string_to_key(context, enctype, &in_string, &in_salt, keyblock);
  caml_acquire_runtime_system();

  krb5_free_data_contents(context, &in_string);

  if(retval) {
    krb5_free_keyblock(context, keyblock);
    CAMLreturn(wrap_result(Val_unit, retval));
  } else {
    o_keyblock = create_krb5_keyblock();
    set_val(krb5_keyblock, o_keyblock, keyblock);

    CAMLreturn(wrap_result(o_keyblock, retval));
  }
}

CAMLprim value
caml_krb5_kt_add_entry(value v_context_token, value v_keytab, value v_keytab_entry)
{
  CAMLparam3(v_context_token, v_keytab, v_keytab_entry);

  krb5_context context = the_context(v_context_token);
  krb5_keytab keytab;
  krb5_error_code retval;
  krb5_keytab_entry *keytab_entry;

  keytab = get_val(krb5_keytab, v_keytab);
  keytab_entry = get_val(krb5_keytab_entry, v_keytab_entry);

  caml_release_runtime_system();
  retval = krb5_kt_add_entry(context, keytab, keytab_entry);
  caml_acquire_runtime_system();

  CAMLreturn(wrap_result(Val_unit, retval));
}

CAMLprim value
caml_krb5_kt_remove_entry(value v_context_token, value v_keytab, value v_keytab_entry)
{
  CAMLparam3(v_context_token, v_keytab, v_keytab_entry);

  krb5_context context = the_context(v_context_token);
  krb5_keytab keytab;
  krb5_error_code retval;
  krb5_keytab_entry *keytab_entry;

  keytab = get_val(krb5_keytab, v_keytab);
  keytab_entry = get_val(krb5_keytab_entry, v_keytab_entry);

  caml_release_runtime_system();
  retval = krb5_kt_remove_entry(context, keytab, keytab_entry);
  caml_acquire_runtime_system();

  CAMLreturn(wrap_result(Val_unit, retval));
}

CAMLprim value
caml_krb5_kt_start_seq_get(value v_context_token, value v_keytab)
{
  CAMLparam2(v_context_token, v_keytab);
  CAMLlocal1(o_cursor);

  krb5_context context = the_context(v_context_token);
  krb5_keytab keytab;
  krb5_kt_cursor cursor;
  krb5_error_code retval;

  keytab = get_val(krb5_keytab, v_keytab);

  caml_release_runtime_system();
  retval = krb5_kt_start_seq_get(context, keytab, &cursor);
  caml_acquire_runtime_system();

  o_cursor = create_krb5_kt_cursor();
  set_val(krb5_kt_cursor, o_cursor, cursor);

  CAMLreturn(wrap_result(o_cursor, retval));
}

CAMLprim value
caml_krb5_kt_next_entry(value v_context_token, value v_keytab, value v_cursor)
{
  CAMLparam3(v_context_token, v_keytab, v_cursor);
  CAMLlocal3(o_entry, o_tuple, o_option);

  krb5_context context = the_context(v_context_token);
  krb5_keytab keytab;
  krb5_kt_cursor cursor;
  krb5_keytab_entry *entry;
  krb5_error_code retval;

  keytab = get_val(krb5_keytab, v_keytab);
  cursor = get_val(krb5_kt_cursor, v_cursor);

  entry = malloc(sizeof(*entry));
  memset(entry, 0, sizeof(*entry));

  caml_release_runtime_system();
  retval = krb5_kt_next_entry(context, keytab, entry, &cursor);
  caml_acquire_runtime_system();

  if (retval == KRB5_KT_END) {
    free(entry);
    CAMLreturn(wrap_result(Val_none, 0));
  }
  else if (retval) {
    free(entry);
    CAMLreturn(wrap_result(Val_unit, retval));
  }
  else {
    /* See comment on [caml_krb5_cc_next_cred]. */
    set_val(krb5_kt_cursor, v_cursor, cursor);

    o_entry = create_krb5_keytab_entry();
    set_val(krb5_keytab_entry, o_entry, entry);

    o_option = caml_alloc_some(o_entry);
    CAMLreturn(wrap_result(o_option, retval));
  }
}

CAMLprim value
caml_krb5_kt_end_seq_get(value v_context_token, value v_keytab, value v_cursor)
{
  CAMLparam3(v_context_token, v_keytab, v_cursor);

  krb5_context context = the_context(v_context_token);
  krb5_keytab keytab;
  krb5_kt_cursor cursor;
  krb5_error_code retval;

  keytab = get_val(krb5_keytab, v_keytab);
  cursor = get_val(krb5_kt_cursor, v_cursor);

  caml_release_runtime_system();
  retval = krb5_kt_end_seq_get(context, keytab, &cursor);
  caml_acquire_runtime_system();

  CAMLreturn(wrap_result(Val_unit, retval));
}

CAMLprim value
caml_krb5_create_keytab_entry(value v_context_token, value v_principal,
                              value v_kvno, value v_keyblock)
{
  CAMLparam4(v_context_token, v_principal, v_kvno, v_keyblock);
  CAMLlocal1(o_keytab_entry);

  krb5_context context = the_context(v_context_token);
  krb5_principal principal;
  krb5_principal principal_copy;
  krb5_error_code retval_principal = 0;
  krb5_timestamp timestamp;
  krb5_kvno kvno;
  krb5_keyblock *keyblock;
  krb5_keyblock *keyblock_copy = NULL;
  krb5_error_code retval_keyblock = 0;
  krb5_keytab_entry *keytab_entry;
  krb5_error_code retval = 0;

  principal = get_val(krb5_principal, v_principal);
  kvno = (krb5_kvno) (Int_val(v_kvno));
  keyblock = get_val(krb5_keyblock, v_keyblock);

  retval = krb5_timeofday(context, &timestamp);
  if (retval) {
    CAMLreturn(wrap_result(Val_unit, retval));
  }

  /* We must copy the keyblock and the principal because
     [krb5_free_keytab_entry_contents] frees both of these. */
  retval_keyblock = krb5_copy_keyblock(context, keyblock, &keyblock_copy);
  retval_principal = krb5_copy_principal(context, principal, &principal_copy);

  if(retval_keyblock || retval_principal) {
    krb5_free_keyblock(context, keyblock_copy);
    krb5_free_principal(context, principal_copy);
    retval = (retval_keyblock != 0) ? retval_keyblock : retval_principal;
    CAMLreturn(wrap_result(Val_unit, retval));
  }
  else {
    keytab_entry = (krb5_keytab_entry *) malloc(sizeof(krb5_keytab_entry));
    memset(keytab_entry, 0, sizeof(*keytab_entry));

    keytab_entry->principal = principal_copy;
    keytab_entry->timestamp = timestamp;
    keytab_entry->vno = kvno;
    /* This creates a shallow copy of [keyblock_copy], thus we need to free the struct
       itself, but not the contained data. */
    keytab_entry->key = *keyblock_copy;
    free(keyblock_copy);

    o_keytab_entry = create_krb5_keytab_entry();
    set_val(krb5_keytab_entry, o_keytab_entry, keytab_entry);

    CAMLreturn(wrap_result(o_keytab_entry, retval));
  }
}

CAMLprim value
caml_krb5_keytab_entry_get_kvno(value v_entry)
{
  CAMLparam1(v_entry);

  krb5_keytab_entry *entry;
  krb5_kvno kvno;

  entry = get_val(krb5_keytab_entry, v_entry);
  kvno = entry->vno;

  CAMLreturn(Val_int (kvno));
}

CAMLprim value
caml_krb5_keytab_entry_get_principal(value v_context_token, value v_entry)
{
  CAMLparam1(v_entry);
  CAMLlocal1(o_principal);

  krb5_context context = the_context(v_context_token);
  krb5_error_code retval;
  krb5_keytab_entry *entry;
  krb5_principal principal;

  entry = get_val(krb5_keytab_entry, v_entry);
  retval = krb5_copy_principal(context, entry->principal, &principal);

  o_principal = create_krb5_principal();
  set_val(krb5_principal, o_principal, principal);

  CAMLreturn(wrap_result(o_principal, retval));
}

CAMLprim value
caml_krb5_keytab_entry_get_keyblock(value v_context_token, value v_entry)
{
  CAMLparam1(v_entry);
  CAMLlocal1(o_keyblock);

  krb5_context context = the_context(v_context_token);
  krb5_error_code retval;
  krb5_keytab_entry *entry;
  krb5_keyblock *keyblock;

  entry = get_val(krb5_keytab_entry, v_entry);

  retval = krb5_copy_keyblock(context, &(entry->key), &keyblock);

  o_keyblock = create_krb5_keyblock();
  set_val(krb5_keyblock, o_keyblock, keyblock);

  CAMLreturn(wrap_result(o_keyblock, retval));
}

CAMLprim value
caml_krb5_keyblock_get_enctype (value v_keyblock)
{
  CAMLparam1(v_keyblock);

  krb5_keyblock *keyblock;
  krb5_enctype enctype;

  keyblock = get_val(krb5_keyblock, v_keyblock);

  enctype = keyblock->enctype;

  CAMLreturn(Val_int(enctype));
}

CAMLprim value
caml_krb5_keyblock_get_key (value v_keyblock)
{
  CAMLparam1(v_keyblock);
  CAMLlocal1(o_key);

  krb5_keyblock *keyblock;

  keyblock = get_val(krb5_keyblock, v_keyblock);

  o_key = caml_alloc_initialized_string(keyblock->length, (char *) keyblock->contents);

  CAMLreturn(o_key);
}

CAMLprim value
caml_krb5_free_keyblock(value v_context_token, value v_keyblock)
{
  CAMLparam2(v_context_token, v_keyblock);

  krb5_context context = the_context(v_context_token);
  krb5_keyblock *keyblock = get_val(krb5_keyblock, v_keyblock);

  krb5_free_keyblock(context, keyblock);

  CAMLreturn(Val_unit);
}

CAMLprim value
caml_krb5_free_keytab_entry(value v_context_token, value v_keytab_entry)
{
  CAMLparam2(v_context_token, v_keytab_entry);

  krb5_context context = the_context(v_context_token);
  krb5_keytab_entry *entry = get_val(krb5_keytab_entry, v_keytab_entry);

  /* The krb5 doc claims this can return an error, but the code always returns 0 in the
     version we are using (1.10.3) (and the latest krb5 release 1.14.2). We call this from
     a finalizer, so we couldn't do any meaningful error handling anyway. */
  krb5_free_keytab_entry_contents(context, entry);
  free(entry);

  CAMLreturn(Val_unit);
}

CAMLprim value
caml_krb5_princ_realm(value v_principal) {
  CAMLparam1(v_principal);
  CAMLlocal1(s);

  krb5_principal principal = get_val(krb5_principal, v_principal);
  krb5_data *realm = &(principal->realm);

  s = caml_alloc_initialized_string(realm->length, realm->data);
  CAMLreturn(s);
}

CAMLprim value
caml_krb5_creds_client(value v_context_token, value v_creds) {
  CAMLparam2(v_context_token, v_creds);
  CAMLlocal1(o_client);

  krb5_context context = the_context(v_context_token);
  krb5_error_code retval;

  krb5_principal principal = get_val(krb5_creds, v_creds).client;
  krb5_principal principal_copy = NULL;

  retval = krb5_copy_principal(context, principal, &principal_copy);
  if(retval) {
    CAMLreturn(wrap_result(Val_unit, retval));
  }

  o_client = create_krb5_principal();
  set_val(krb5_principal, o_client, principal_copy);

  CAMLreturn(wrap_result(o_client, retval));
}

CAMLprim value
caml_krb5_creds_server(value v_context_token, value v_creds) {
  CAMLparam2(v_context_token, v_creds);
  CAMLlocal1(o_server);

  krb5_context context = the_context(v_context_token);
  krb5_error_code retval;

  krb5_principal principal = get_val(krb5_creds, v_creds).server;
  krb5_principal principal_copy = NULL;

  retval = krb5_copy_principal(context, principal, &principal_copy);
  if(retval) {
    CAMLreturn(wrap_result(Val_unit, retval));
  }

  o_server = create_krb5_principal();
  set_val(krb5_principal, o_server, principal_copy);

  CAMLreturn(wrap_result(o_server, retval));
}

CAMLprim value
caml_krb5_creds_is_skey(value v_creds) {
  CAMLparam1(v_creds);
  CAMLlocal1(o_is_skey);

  krb5_boolean is_skey = get_val(krb5_creds, v_creds).is_skey;

  o_is_skey = Val_bool(is_skey);

  CAMLreturn(o_is_skey);
}


CAMLprim value
caml_krb5_creds_ticket_data(value v_context_token, value v_creds) {
  CAMLparam2(v_context_token, v_creds);
  CAMLlocal1(o_data);

  krb5_context context = the_context(v_context_token);
  krb5_error_code retval;

  krb5_creds creds = get_val(krb5_creds, v_creds);
  krb5_data data = creds.ticket;
  krb5_data* data_copy = NULL;

  retval = krb5_copy_data(context, &data, &data_copy);
  if (retval) {
    CAMLreturn(wrap_result(Val_unit, retval));
  }

  o_data = create_krb5_data();
  set_val(krb5_data, o_data, *data_copy);

  /* krb5_copy_data allocates a new krb5_data structure (data_copy)
     which must be freed after its contents are copied into the
     gc-tracked structure (o_data) */
  free(data_copy);

  CAMLreturn(wrap_result(o_data, retval));
}

CAMLprim value
caml_krb5_creds_ticket_string(value v_creds) {
  CAMLparam1(v_creds);
  CAMLlocal1(o_ticket);

  krb5_data ticket = get_val(krb5_creds, v_creds).ticket;

  o_ticket = caml_alloc_initialized_string(ticket.length, ticket.data);

  CAMLreturn(o_ticket);
}

CAMLprim value
caml_krb5_creds_second_ticket(value v_creds) {
  CAMLparam1(v_creds);
  CAMLlocal1(o_second_ticket);

  krb5_data second_ticket = get_val(krb5_creds, v_creds).second_ticket;

  o_second_ticket = caml_alloc_initialized_string(second_ticket.length, second_ticket.data);

  CAMLreturn(o_second_ticket);
}

CAMLprim value
caml_krb5_creds_starttime(value v_creds) {
  CAMLparam1(v_creds);

  krb5_ticket_times times = get_val(krb5_creds, v_creds).times;
  CAMLreturn(Val_int(times.starttime));
}

CAMLprim value
caml_krb5_creds_endtime(value v_creds) {
  CAMLparam1(v_creds);

  krb5_ticket_times times = get_val(krb5_creds, v_creds).times;
  CAMLreturn(Val_int(times.endtime));
}

CAMLprim value
caml_krb5_creds_renew_till(value v_creds) {
  CAMLparam1(v_creds);

  krb5_ticket_times times = get_val(krb5_creds, v_creds).times;
  CAMLreturn(Val_int(times.renew_till));
}

CAMLprim value
caml_krb5_creds_forwardable(value v_creds) {
  CAMLparam1(v_creds);

  krb5_flags flags = get_val(krb5_creds, v_creds).ticket_flags;
  CAMLreturn(Val_bool(flags & TKT_FLG_FORWARDABLE));
}

CAMLprim value
caml_krb5_creds_proxiable(value v_creds) {
  CAMLparam1(v_creds);

  krb5_flags flags = get_val(krb5_creds, v_creds).ticket_flags;
  CAMLreturn(Val_bool(flags & TKT_FLG_PROXIABLE));
}

CAMLprim value
caml_krb5_creds_keyblock(value v_context_token, value v_creds) {
  CAMLparam2(v_context_token, v_creds);
  CAMLlocal1(o_keyblock);

  krb5_context context = the_context(v_context_token);
  krb5_keyblock keyblock = get_val(krb5_creds, v_creds).keyblock;
  krb5_keyblock *keyblock_copy = NULL;
  krb5_error_code retval;

  retval = krb5_copy_keyblock(context,
                              &keyblock,
                              &keyblock_copy);

  if(retval) {
    CAMLreturn(wrap_result(Val_unit, retval));
  } else {
    o_keyblock = create_krb5_keyblock();
    set_val(krb5_keyblock, o_keyblock, keyblock_copy);

    CAMLreturn(wrap_result(o_keyblock, retval));
  }
}

CAMLprim value
caml_krb5_auth_con_setuseruserkey(value v_context_token, value v_auth_context,
                                  value v_keyblock) {
  CAMLparam3(v_context_token, v_auth_context, v_keyblock);

  krb5_context context = the_context(v_context_token);
  krb5_error_code retval;

  retval = krb5_auth_con_setuseruserkey(context,
                                        get_val(krb5_auth_context, v_auth_context),
                                        get_val(krb5_keyblock, v_keyblock));

  CAMLreturn(wrap_result(Val_unit, retval));
}

CAMLprim value
caml_krb5_creds_create(value v_context_token, value v_client,
                       value v_server, value v_ticket_opt, value v_second_ticket_opt) {
  CAMLparam5(v_context_token, v_client, v_server, v_ticket_opt, v_second_ticket_opt);
  CAMLlocal3(o_creds, v_ticket, v_second_ticket);

  krb5_creds creds;
  krb5_error_code retval;

  krb5_context context = the_context(v_context_token);
  krb5_principal client_princ = get_val(krb5_principal, v_client);
  krb5_principal server_princ = get_val(krb5_principal, v_server);

  memset(&creds, 0, sizeof(creds));

  if(Is_block(v_ticket_opt)) {
    v_ticket = Field(v_ticket_opt, 0);

    creds.ticket.length = caml_string_length(v_ticket);
    creds.ticket.data = malloc(creds.ticket.length);
    memcpy(creds.ticket.data, String_val(v_ticket), creds.ticket.length);
  }

  if(Is_block(v_second_ticket_opt)) {
    v_second_ticket = Field(v_second_ticket_opt, 0);

    creds.second_ticket.length = caml_string_length(v_second_ticket);
    creds.second_ticket.data = malloc(creds.second_ticket.length);
    memcpy(creds.second_ticket.data, String_val(v_second_ticket), creds.second_ticket.length);
  }

  retval = krb5_copy_principal(context, client_princ, &(creds.client));
  if(retval) {
    free(creds.ticket.data);
    free(creds.second_ticket.data);

    CAMLreturn(wrap_result(Val_unit, retval));
  }

  retval = krb5_copy_principal(context, server_princ, &(creds.server));
  if(retval) {
    free(creds.ticket.data);
    free(creds.second_ticket.data);
    krb5_free_principal(context, creds.client);

    CAMLreturn(wrap_result(Val_unit, retval));
  }

  o_creds = create_krb5_creds();
  set_val(krb5_creds, o_creds, creds);

  CAMLreturn(wrap_result(o_creds, retval));
}

CAMLprim value
caml_krb5_get_credentials(value v_context_token, value v_options,
                          value v_ccache, value v_in_creds) {
  CAMLparam4(v_context_token, v_options, v_ccache, v_in_creds);
  CAMLlocal1(o_out_creds);

  krb5_context context = the_context(v_context_token);
  krb5_flags options = 0;
  krb5_creds in_creds = get_val(krb5_creds, v_in_creds);
  krb5_creds *out_creds;
  krb5_error_code retval;
  krb5_ccache ccache = get_val(krb5_ccache, v_ccache);

  while(v_options != Val_int(0)) {
    switch(Int_val(Field(v_options, 0))) {
    case 0: options |= KRB5_GC_CACHED;    break;
    case 1: options |= KRB5_GC_USER_USER; break;
    case 2: options |= KRB5_GC_NO_STORE;  break;
    default:
      caml_invalid_argument("krb5_get_credentials: invalid krb5_flags");
    }

    v_options = Field(v_options, 1);
  }

  caml_release_runtime_system();
  retval = krb5_get_credentials(context,
                                options,
                                ccache,
                                &in_creds,
                                &out_creds);
  caml_acquire_runtime_system();

  if(retval) {
    CAMLreturn(wrap_result(Val_unit, retval));
  } else {
    o_out_creds = create_krb5_creds();
    set_val(krb5_creds, o_out_creds, *out_creds);
    /* We make a copy of the top-level struct, so we need to free it. We can't use
       krb5_free_creds, since that would also free the contained malloc'ed data regions */
    free(out_creds);

    CAMLreturn(wrap_result(o_out_creds, retval));
  }
}

CAMLprim value
caml_krb5_mk_req_extended(value v_context_token, value v_auth_context,
                          value v_req_flags, value v_creds) {
  CAMLparam4(v_context_token, v_auth_context, v_req_flags, v_creds);

  krb5_context context = the_context(v_context_token);
  krb5_error_code retval;
  krb5_data outbuf;
  krb5_flags flags = 0;
  krb5_auth_context auth_context = get_val(krb5_auth_context, v_auth_context);
  krb5_creds creds = get_val(krb5_creds, v_creds);

  while(v_req_flags != Val_int(0)) {
    switch(Int_val(Field(v_req_flags, 0))) {
    case 0: flags |= AP_OPTS_USE_SESSION_KEY; break;
    case 1: flags |= AP_OPTS_MUTUAL_REQUIRED; break;
    default: caml_invalid_argument("my_krb5_mk_req_extended: invalid krb5_mk_req_flag");
    }

    v_req_flags = Field(v_req_flags, 1);
  }

  retval = krb5_mk_req_extended(context,
                                &auth_context,
                                flags,
                                NULL,
                                &creds,
                                &outbuf);

  CAMLreturn(handle_outbuffer(&outbuf, retval));
}

CAMLprim value
caml_krb5_fwd_tgt_cred(value v_context_token, value v_auth_context, value v_client,
                       value v_ccache, value v_forwardable) {
  CAMLparam5(v_context_token, v_auth_context, v_client, v_ccache, v_forwardable);

  krb5_context context = the_context(v_context_token);
  krb5_auth_context auth_context = get_val(krb5_auth_context, v_auth_context);
  krb5_principal client = get_val(krb5_principal, v_client);
  krb5_ccache ccache = get_val(krb5_ccache, v_ccache);
  krb5_boolean forwardable = Bool_val(v_forwardable);
  krb5_error_code retval;
  krb5_data outbuf;

  /* [krb5_fwd_tgt_creds] is a thin wrapper around [krb5_make_1cred]. The former does some
     nice things with regard to addresses in tickets, but we don't currently have
     addresses in tickets, so we pass NULL for rhost and server. It still uses the
     existing tgt to get a new tgt, which is the proper way to forward credentials. */
  caml_release_runtime_system();
  retval = krb5_fwd_tgt_creds(context,
                              auth_context,
                              NULL, /* rhost */
                              client,
                              NULL, /* server */
                              ccache,
                              forwardable,
                              &outbuf);
  caml_acquire_runtime_system();

  CAMLreturn(handle_outbuffer(&outbuf, retval));
}

/* call krb5_rd_cred and store each resulting [Credentials.t] in the given cred cache */
CAMLprim value
caml_krb5_cc_store_krb_cred(value v_context_token,
                            value v_auth_context,
                            value v_ccache,
                            value v_cred_data
                            ) {
  CAMLparam4(v_context_token, v_auth_context, v_ccache, v_cred_data);

  krb5_context context = the_context(v_context_token);
  krb5_auth_context auth_context = get_val(krb5_auth_context, v_auth_context);
  krb5_ccache ccache = get_val(krb5_ccache, v_ccache);
  krb5_data cred_data = data_of_bigstring(v_cred_data);

  krb5_creds **ppcreds;
  krb5_creds **i;
  krb5_error_code retval;

  caml_release_runtime_system();
  retval = krb5_rd_cred(context,
                        auth_context,
                        &cred_data,
                        &ppcreds,
                        NULL);
  if(retval) {
    caml_acquire_runtime_system();
    CAMLreturn(wrap_result(Val_unit, retval));
  }

  for (i = ppcreds; *i; i++) {
    retval = krb5_cc_store_cred (context, ccache, *i);
    if(retval) {
      krb5_free_tgt_creds(context, ppcreds);
      caml_acquire_runtime_system();
      CAMLreturn(wrap_result(Val_unit, retval));
    }
  }

  krb5_free_tgt_creds(context, ppcreds);
  caml_acquire_runtime_system();
  CAMLreturn(wrap_result(Val_unit, 0));
}

CAMLprim value
caml_krb5_decode_ticket(value v_data) {
  CAMLparam1(v_data);
  CAMLlocal1(o_ticket);

  krb5_ticket* ticket = NULL;
  krb5_error_code retval;

  krb5_data ticket_data = get_val(krb5_data, v_data);
  retval = krb5_decode_ticket(&ticket_data, &ticket);
  if (retval) {
    CAMLreturn(wrap_result(Val_unit, retval));
  }

  o_ticket = create_krb5_ticket();
  set_val(krb5_ticket, o_ticket, ticket);

  CAMLreturn(wrap_result(o_ticket, retval));
}

CAMLprim value
caml_krb5_free_ticket(value v_context_token, value v_ticket) {
  CAMLparam2(v_context_token, v_ticket);

  krb5_context context = the_context(v_context_token);
  krb5_ticket* ticket = get_val(krb5_ticket, v_ticket);

  krb5_free_ticket(context, ticket);
  CAMLreturn(Val_unit);
}

CAMLprim value
caml_krb5_ticket_kvno(value v_ticket) {
  CAMLparam1(v_ticket);

  krb5_ticket* ticket = get_val(krb5_ticket, v_ticket);
  krb5_enc_data enc_part = ticket->enc_part;
  krb5_kvno kvno = enc_part.kvno;

  CAMLreturn(Val_int(kvno));
}

CAMLprim value
caml_krb5_ticket_enctype(value v_ticket) {
  CAMLparam1(v_ticket);

  krb5_ticket* ticket = get_val(krb5_ticket, v_ticket);
  krb5_enc_data enc_part = ticket->enc_part;
  krb5_enctype enc_type = enc_part.enctype;

  CAMLreturn(Val_int(enc_type));
}
