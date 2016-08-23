/* Copyright (C) 2016 Kirk Zurell.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

/* guile-linux-key-retention */

#include <errno.h>
#include <limits.h>

#include <libguile.h>

#include <keyutils.h>

/* ******************************************************************
   Support routines to match libguile usage. 
*/

/* This is probably not the correct way to do this. */
#define scm_is_undefined(x) (scm_is_eq(x, SCM_UNDEFINED))


#define KEY_SERIAL_DESC "NUM"

SCM 
scm_from_key_serial_t(key_serial_t x)
{
  return scm_from_int((int)x);
}

key_serial_t
scm_to_key_serial_t(SCM x)
{
  return scm_to_int(x);
}

int
scm_is_key_serial_t(SCM x)
{
  return scm_is_number(x);
}



/* ******************************************************************
   Methods 
*/



SCM
add_key_wrapper (SCM keytype, SCM description, SCM payload, SCM keyring)
{
  key_serial_t result = NULL;

  char *req_keytype = NULL;
  char *req_description = NULL;

  void * req_payload = NULL;
  size_t req_plen = 0;
  
  key_serial_t req_keyring = NULL;

  SCM_ASSERT_TYPE(scm_is_string(keytype), keytype, SCM_ARG1, "add-key", "STRING" );
  SCM_ASSERT_TYPE(scm_is_string(description), description, SCM_ARG2, "add-key", "STRING" );
  SCM_ASSERT_TYPE(scm_is_string(payload) 
		  || scm_is_false(payload)
		  || scm_is_undefined(payload),
		  payload, SCM_ARG3, "add-key", "STRING or #f" );
  SCM_ASSERT_TYPE(scm_is_key_serial_t(keyring)
		  || scm_is_undefined(keyring), 
		  keyring, SCM_ARG4, "add-key", KEY_SERIAL_DESC );

  scm_dynwind_begin(0);

  req_keytype = scm_to_locale_string(keytype);
  scm_dynwind_free(req_keytype);

  req_description = scm_to_locale_string(description);
  scm_dynwind_free(req_description);

  if(!(scm_is_false(payload) || scm_is_undefined(payload)))
    {
      req_payload = scm_to_locale_string(payload);
      scm_dynwind_free(req_payload);
      req_plen = strlen(req_payload);
    }

  if(scm_is_key_serial_t(keyring))
    {
      req_keyring = scm_to_key_serial_t(keyring);
    }

  result = add_key(req_keytype, req_description, req_payload, req_plen, req_keyring);

  scm_dynwind_end();

  if(result < 0)
    {
      scm_syserror("add-key");
    }

  return scm_from_key_serial_t(result);
}




SCM
request_key_wrapper (SCM keytype, SCM description, SCM callout_info, SCM dest_keyring)
{
  key_serial_t result = NULL;

  char *req_keytype = NULL;
  char *req_description = NULL;
  void *req_callout_info = NULL;
  key_serial_t req_dest_keyring = NULL;

  SCM_ASSERT_TYPE(scm_is_string(keytype), keytype, SCM_ARG1, "request-key", "STRING" );
  SCM_ASSERT_TYPE(scm_is_string(description), description, SCM_ARG2, "request-key", "STRING" );
  SCM_ASSERT_TYPE(scm_is_string(callout_info)
		  || scm_is_false(callout_info)
		  || scm_is_undefined(callout_info), 
		  keytype, SCM_ARG3, "request-key", "STRING or #f" );
  SCM_ASSERT_TYPE(scm_is_key_serial_t(dest_keyring)
		  || scm_is_false(dest_keyring)
		  || scm_is_undefined(dest_keyring), 
		  keytype, SCM_ARG4, "request-key", KEY_SERIAL_DESC " or #f" );

  scm_dynwind_begin(0);

  req_keytype = scm_to_locale_string(keytype);
  scm_dynwind_free(req_keytype);

  req_description = scm_to_locale_string(description);
  scm_dynwind_free(req_description);

  if(!(scm_is_false(callout_info) || scm_is_undefined(callout_info)))
    {
      req_callout_info = scm_to_locale_string(callout_info);
      scm_dynwind_free(req_callout_info);
    }

  if(scm_is_key_serial_t(dest_keyring))
    {
      req_dest_keyring = scm_to_key_serial_t(dest_keyring);
    }

  result = request_key(req_keytype, req_description, req_callout_info, req_dest_keyring);

  scm_dynwind_end();
  
  if(result < 0) {
    scm_syserror("request-key");
  }

  return scm_from_key_serial_t(result);

}




SCM
keyctl_get_keyring_ID_wrapper(SCM id, SCM create)
{
  key_serial_t result = NULL;

  key_serial_t req_id = NULL;
  int req_create = 0;
  
  SCM_ASSERT_TYPE(scm_is_key_serial_t(id), id, SCM_ARG1, "keyctl-get-keyring-ID", KEY_SERIAL_DESC );
  SCM_ASSERT_TYPE(scm_is_bool(create)
		  || scm_is_undefined(create), 
		  create, SCM_ARG2, "keyctl-get-keyring-ID", "BOOL");
  
  req_id = scm_to_key_serial_t(id);

  if(scm_is_bool(create))
    {
      req_create = scm_to_bool(create);
    }

  result = keyctl(KEYCTL_GET_KEYRING_ID, req_id, req_create);
  
  if(result < 0) //ENOKEY
    {
      scm_syserror("keyctl-get-keyring-ID");
    }

  return scm_from_key_serial_t(result);
}



SCM
keyctl_join_session_keyring_wrapper(SCM name)
{
  key_serial_t result;
  char *req_name = NULL;
  
  SCM_ASSERT_TYPE(scm_is_string(name) 
		  || scm_is_false(name)
		  || scm_is_undefined(name), 
		  name, SCM_ARG1, "keyctl-join-session-keyring", "STRING or #f");
  
  scm_dynwind_begin(0);

  if(scm_is_string(name))
    {
      req_name = scm_to_locale_string(name);
      scm_dynwind_free(req_name);      
    }

  result = keyctl(KEYCTL_JOIN_SESSION_KEYRING, req_name);
  
  scm_dynwind_end();

  if(result < 0) 
    {
      scm_syserror("keyctl-join-session-keyring");
    }

  return scm_from_key_serial_t(result);
}



SCM
keyctl_update_wrapper(SCM key, SCM payload)
{
  long result = 0;

  key_serial_t req_key = NULL;

  void * req_payload = NULL;
  size_t req_plen = 0;
  
  SCM_ASSERT_TYPE(scm_is_key_serial_t(key), key, SCM_ARG1, "keyctl-update", KEY_SERIAL_DESC );
  SCM_ASSERT_TYPE(scm_is_string(payload)
		  || scm_is_false(payload)
		  || scm_is_undefined(payload), 
		  payload, SCM_ARG2, "keyctl-update", "STRING" );
  
  scm_dynwind_begin(0);

  req_key = scm_to_key_serial_t(key);

  if(scm_is_string(payload))
    {
      req_payload = scm_to_locale_string(payload);
      scm_dynwind_free(req_payload);
      req_plen = strlen(req_payload);
    }

  result = keyctl(KEYCTL_UPDATE, req_key, req_payload, req_plen);

  scm_dynwind_end();

  if(result < 0)
    {
      scm_syserror("keyctl-update");
    }

  return scm_from_long(result);
}


SCM
keyctl_revoke_wrapper(SCM key)
{ 
  long result;
  
  key_serial_t req_key = NULL;

  SCM_ASSERT_TYPE(scm_is_key_serial_t(key), key, SCM_ARG1, "keyctl-revoke", KEY_SERIAL_DESC);
  
  req_key = scm_to_key_serial_t(key);

  result = keyctl(KEYCTL_REVOKE, req_key);
  
  if(result < 0)
    {
      scm_syserror("keyctl-revoke");
    }

  return result == 0 ? SCM_BOOL_T : scm_from_long(result);
}



SCM
keyctl_chown_wrapper(SCM key, SCM uid, SCM gid)
{
  long result = 0;
  key_serial_t req_key = NULL;
  uid_t req_uid = -1;
  gid_t req_gid = -1;

  SCM_ASSERT_TYPE(scm_is_key_serial_t(key), key, SCM_ARG1, "keyctl-chown", KEY_SERIAL_DESC);
  SCM_ASSERT_TYPE(scm_is_number(uid) 
		  || scm_is_false(uid) 
		  || scm_is_undefined(uid),
		  uid, SCM_ARG2, "keyctl-chown", KEY_SERIAL_DESC " or #f");
  SCM_ASSERT_TYPE(scm_is_number(gid)
		  || scm_is_false(gid)
		  || scm_is_undefined(gid),
		  gid, SCM_ARG3, "keyctl-chown", KEY_SERIAL_DESC " or #f");

  req_key = scm_to_key_serial_t(key);

  if(scm_is_number(uid))
    {
      req_uid = (uid_t)scm_to_signed_integer(uid, -1, INT_MAX);
    }

  if(scm_is_number(gid))
    {
      req_gid = (gid_t)scm_to_signed_integer(uid, -1, INT_MAX);
    }

  result = keyctl(KEYCTL_CHOWN, req_key, req_uid, req_gid);

  if(result < 0)
    {
      scm_syserror("keyctl-update");
    }

  return scm_from_long(result);
}



SCM
keyctl_setperm_wrapper(SCM key, SCM perm)
{
  long result = 0;
  key_serial_t req_key = NULL;
  key_perm_t req_perm = 0;

  SCM_ASSERT_TYPE(scm_is_key_serial_t(key), key, SCM_ARG1, "keyctl-setperm", KEY_SERIAL_DESC);
  SCM_ASSERT_TYPE(scm_is_number(perm), perm, SCM_ARG2, "keyctl-setperm", KEY_SERIAL_DESC);

  req_key = scm_to_key_serial_t(key);

  req_perm = (key_perm_t)scm_to_uint32(perm);

  result = keyctl(KEYCTL_SETPERM, req_key, req_perm);

  if(result < 0)
    {
      scm_syserror("keyctl-setperm");
    }

  return scm_from_long(result);
}



SCM
keyctl_describe_wrapper(SCM key)
{
  long result = 0;

  key_serial_t req_key = NULL;
  char req_buffer[256];

  SCM_ASSERT_TYPE(scm_is_key_serial_t(key), key, SCM_ARG1, "keyctl-describe", KEY_SERIAL_DESC);

  req_key = scm_to_key_serial_t(key);

  result = keyctl(KEYCTL_DESCRIBE, req_key, req_buffer, 256);

  if(result < 0)
    {
      scm_syserror("keyctl-describe");
    }

  result = result > 256 ? 256 : result;

  // Remove final zero.
  return scm_from_locale_stringn(req_buffer, result - 1);
}



SCM
keyctl_clear_wrapper(SCM keyring)
{
  long result = 0;

  key_serial_t req_keyring = NULL;
  
  SCM_ASSERT_TYPE(scm_is_key_serial_t(keyring), keyring, SCM_ARG1, "keyctl-clear", KEY_SERIAL_DESC);
  
  req_keyring = scm_to_key_serial_t(keyring);

  result = keyctl(KEYCTL_CLEAR, req_keyring);

  if(result < 0)
    {
      scm_syserror("keyctl-clear");
    }
  
  return SCM_BOOL_T;
}



SCM
keyctl_link_wrapper(SCM keyring, SCM key)
{
  long result = 0;
  key_serial_t req_keyring = NULL;
  key_serial_t req_key = NULL;

  SCM_ASSERT_TYPE(scm_is_key_serial_t(keyring), keyring, SCM_ARG1, "keyctl-link", KEY_SERIAL_DESC);
  SCM_ASSERT_TYPE(scm_is_key_serial_t(key), key, SCM_ARG2, "keyctl-link", KEY_SERIAL_DESC);

  req_keyring = scm_to_key_serial_t(keyring);

  req_key = scm_to_key_serial_t(key);

  result = keyctl(KEYCTL_LINK, req_keyring, req_key);

  if(result < 0)
    {
      scm_syserror("keyctl-link");
    }
  
  return result ? scm_from_long(result) : SCM_BOOL_T;
}



SCM
keyctl_unlink_wrapper(SCM keyring, SCM key)
{
  long result = 0;
  key_serial_t req_keyring = NULL;
  key_serial_t req_key = NULL;

  SCM_ASSERT_TYPE(scm_is_key_serial_t(keyring), keyring, SCM_ARG1, "keyctl-unlink", KEY_SERIAL_DESC);
  SCM_ASSERT_TYPE(scm_is_key_serial_t(key), key, SCM_ARG2, "keyctl-unlink", KEY_SERIAL_DESC);

  req_keyring = scm_to_key_serial_t(keyring);

  req_key = scm_to_key_serial_t(key);

  result = keyctl(KEYCTL_UNLINK, req_keyring, req_key);

  if(result < 0)
    {
      scm_syserror("keyctl-unlink");
    }
  
  return result ? scm_from_long(result) : SCM_BOOL_T;
}




SCM
keyctl_search_wrapper(SCM keyring, SCM keytype, SCM description, SCM dest_keyring)
{
  key_serial_t result = NULL;
  key_serial_t req_keyring = NULL;
  char * req_keytype = NULL;
  char * req_description = NULL;
  key_serial_t req_dest_keyring = NULL;

  SCM_ASSERT_TYPE(scm_is_key_serial_t(keyring), keyring, SCM_ARG1, "keyctl-search", KEY_SERIAL_DESC);
  SCM_ASSERT_TYPE(scm_is_string(keytype), keytype, SCM_ARG2, "keyctl-search", "STRING");
  SCM_ASSERT_TYPE(scm_is_string(description), description, SCM_ARG3, "keyctl-search", "STRING");
  SCM_ASSERT_TYPE(scm_is_key_serial_t(dest_keyring) 
		  || scm_is_false(dest_keyring)
		  || scm_is_undefined(dest_keyring), 
		  dest_keyring, SCM_ARG4, "keyctl-search", KEY_SERIAL_DESC);
  
  scm_dynwind_begin(0);

  req_keyring = scm_to_key_serial_t(keyring);
  
  req_keytype = scm_to_locale_string(keytype);
  scm_dynwind_free(req_keytype);

  req_description = scm_to_locale_string(description);
  scm_dynwind_free(req_description);

  if(scm_is_key_serial_t(dest_keyring))
    {
      req_dest_keyring = scm_to_key_serial_t(dest_keyring);
    }

  result = keyctl(KEYCTL_SEARCH, req_keyring, req_keytype, req_description, req_dest_keyring);

  scm_dynwind_end();

  if(result < 0)
    {
      scm_syserror("keyctl-search");
    }

  return result ? scm_from_key_serial_t(result) : SCM_BOOL_T;
}



SCM
keyctl_read_wrapper(SCM key)
{
  long result = 0;

  key_serial_t req_key = NULL;
  char req_buffer[256];
  
  SCM_ASSERT_TYPE(scm_is_key_serial_t(key), key, SCM_ARG1, "keyctl-read", KEY_SERIAL_DESC);

  req_key = scm_to_key_serial_t(key);

  result = keyctl(KEYCTL_READ, req_key, req_buffer, 256);

  if(result < 0)
    {
      scm_syserror("keyctl-read");
    }

  result = result > 256 ? 256 : result;

  return result ? scm_from_locale_stringn(req_buffer, result) : SCM_BOOL_F;
}



SCM
keyctl_instantiate_wrapper(SCM key, SCM payload, SCM keyring)
{
  return SCM_UNDEFINED;
}



SCM
keyctl_negate_wrapper(SCM key, SCM timeout, SCM keyring)
{
  long result = 0;

  key_serial_t req_key = NULL;
  unsigned req_timeout = 0;
  key_serial_t req_keyring = NULL;

  SCM_ASSERT_TYPE(scm_is_key_serial_t(key), key, SCM_ARG1, "keyctl-negate", KEY_SERIAL_DESC );  
  SCM_ASSERT_TYPE(scm_is_number(timeout), timeout, SCM_ARG2, "keyctl-negate", KEY_SERIAL_DESC );
  SCM_ASSERT_TYPE(scm_is_key_serial_t(keyring) 
		  || scm_is_false(keyring)
		  || scm_is_undefined(keyring), 
		  keyring, SCM_ARG3, "keyctl-negate", KEY_SERIAL_DESC " or #f" );  

  req_key = scm_to_key_serial_t(key);

  req_timeout = scm_to_unsigned_integer(timeout, 0, INT_MAX);

  if(scm_is_key_serial_t(keyring))
    {
      req_keyring = scm_to_key_serial_t(keyring);
    }

  result = keyctl(KEYCTL_NEGATE, req_key, req_timeout, req_keyring);

  if(result < 0)
    {
      scm_syserror("keyctl-negate");
    }

  // What does this result mean?
  return scm_from_long(result);
}



SCM
keyctl_reject_wrapper(SCM key, SCM timeout, SCM error, SCM keyring)
{
  long result = 0;

  key_serial_t req_key = NULL;
  unsigned req_timeout = 0;
  unsigned req_error = 0;
  key_serial_t req_keyring = NULL;

  SCM_ASSERT_TYPE(scm_is_key_serial_t(key), key, SCM_ARG1, "keyctl-reject", KEY_SERIAL_DESC );  
  SCM_ASSERT_TYPE(scm_is_number(timeout), timeout, SCM_ARG2, "keyctl-reject", KEY_SERIAL_DESC );
  SCM_ASSERT_TYPE(scm_is_number(error), error, SCM_ARG3, "keyctl-reject", KEY_SERIAL_DESC );
  SCM_ASSERT_TYPE(scm_is_key_serial_t(keyring) 
		  || scm_is_false(keyring)
		  || scm_is_undefined(keyring), 
		  keyring, SCM_ARG4, "keyctl-reject", KEY_SERIAL_DESC " or #f" );  

  req_key = scm_to_key_serial_t(key);

  req_timeout = scm_to_unsigned_integer(timeout, 0, INT_MAX);

  req_error = scm_to_unsigned_integer(error, 0, INT_MAX);

  if(scm_is_key_serial_t(keyring))
    {
      req_keyring = scm_to_key_serial_t(keyring);
    }

  result = keyctl(KEYCTL_NEGATE, req_key, req_timeout, req_keyring);

  if(result < 0)
    {
      scm_syserror("keyctl-reject");
    }

  return scm_from_long(result);
}



SCM
keyctl_set_reqkey_keyring_wrapper(SCM reqkey_defl)
{
  long result = 0;

  int req_reqkey_defl = NULL;

  SCM_ASSERT_TYPE(scm_is_signed_integer(reqkey_defl, INT_MIN, INT_MAX), 
		  reqkey_defl, SCM_ARG1, "keyctl-set-reqkey", KEY_SERIAL_DESC );

  req_reqkey_defl = scm_to_signed_integer(reqkey_defl, INT_MIN, INT_MAX);

  result = keyctl(KEYCTL_SET_REQKEY_KEYRING, req_reqkey_defl);

  if(result < 0)
    {
      scm_syserror("keyctl-set-reqkey-keyring");
    }

  return scm_from_long(result);
}



SCM
keyctl_set_timeout_wrapper(SCM key, SCM timeout)
{
  long result = 0;

  key_serial_t req_key = NULL;
  /* KEYCTL_SET_TIMEOUT parameter is unsigned implied int. */
  unsigned req_timeout = 0;

  SCM_ASSERT_TYPE(scm_is_key_serial_t(key), key, SCM_ARG1, "keyctl-set-timeout", KEY_SERIAL_DESC );  
  SCM_ASSERT_TYPE(scm_is_unsigned_integer(timeout, 0, INT_MAX), timeout, SCM_ARG2, "keyctl-set-timeout", KEY_SERIAL_DESC );

  req_key = scm_to_key_serial_t(key);

  req_timeout = scm_to_unsigned_integer(timeout, 0, INT_MAX); // TODO: check range.

  result = keyctl(KEYCTL_SET_TIMEOUT, req_key, req_timeout); 
   
  if(result < 0)
    {
      scm_syserror("keyctl-set-timeout");
    }

  return result ? scm_from_long(result) : SCM_BOOL_T;
}



SCM
keyctl_assume_authority_wrapper(SCM key)
{
  long result = 0;

  key_serial_t req_key = NULL;

  SCM_ASSERT_TYPE(scm_is_key_serial_t(key)
		  || scm_is_false(key)
		  || scm_is_undefined(key), 
		  key, SCM_ARG1, "keyctl-set-timeout", KEY_SERIAL_DESC );  
  
  if(scm_is_key_serial_t(key))
    {
      req_key = scm_to_key_serial_t(key);
    }

  result = keyctl(KEYCTL_ASSUME_AUTHORITY, req_key);

  return result ? scm_from_long(result) : SCM_BOOL_T ;
}



SCM
keyctl_get_security_wrapper(SCM key)
{
  long result = 0;

  key_serial_t req_key = NULL;
  char req_buffer[256];

  SCM_ASSERT_TYPE(scm_is_key_serial_t(key), key, SCM_ARG1, "keyctl-get-security", KEY_SERIAL_DESC);

  req_key = scm_to_key_serial_t(key);

  result = keyctl(KEYCTL_GET_SECURITY, req_key, req_buffer, 256);

  if(result < 0)
    {
      scm_syserror("keyctl-get-security");
    }
  
  result = result > 256 ? 256 : result;

  // Remove final zero.
  return scm_from_locale_stringn(req_buffer, result - 1);
}



SCM
keyctl_session_to_parent_wrapper(void)
{
  long result = 0;

  result = keyctl(KEYCTL_SESSION_TO_PARENT);

  if(result < 0)
    {
      scm_syserror("keyctl-session-to-parent");
    }

  return result ? scm_from_long(result) : SCM_BOOL_T;
}



SCM
keyctl_invalidate_wrapper(SCM key)
{
  long result = 0;
  key_serial_t req_key = NULL;

  SCM_ASSERT_TYPE(scm_is_key_serial_t(key), key, SCM_ARG1, "keyctl-invalidate", KEY_SERIAL_DESC );

  req_key = scm_to_key_serial_t(key);

  result = keyctl(KEYCTL_INVALIDATE, req_key);

  if(result < 0)
    {
      scm_syserror("keyctl-invalidate");
    }

  return result ? scm_from_long(result) : SCM_BOOL_T;
}


/* ******************************************************************
   Initialization
*/

void
init_linux_key_retention (void)
{

  /* Keyring identifiers */

  scm_c_define("KEY_SPEC_THREAD_KEYRING", scm_from_signed_integer(KEY_SPEC_THREAD_KEYRING)); // -1 thread-specific keyring
  scm_c_define("KEY_SPEC_PROCESS_KEYRING", scm_from_signed_integer(KEY_SPEC_PROCESS_KEYRING)); // -2 process-specific keyring
  scm_c_define("KEY_SPEC_SESSION_KEYRING", scm_from_signed_integer(KEY_SPEC_SESSION_KEYRING)); // -3 session-specific keyring
  scm_c_define("KEY_SPEC_USER_KEYRING", scm_from_signed_integer(KEY_SPEC_USER_KEYRING)); // -4 UID-specific keyring
  scm_c_define("KEY_SPEC_USER_SESSION_KEYRING", scm_from_signed_integer(KEY_SPEC_USER_SESSION_KEYRING)); // -5 UID-session keyring
  scm_c_define("KEY_SPEC_GROUP_KEYRING", scm_from_signed_integer(KEY_SPEC_GROUP_KEYRING)); // -6 GID-specific keyring
  scm_c_define("KEY_SPEC_REQKEY_AUTH_KEY", scm_from_signed_integer(KEY_SPEC_REQKEY_AUTH_KEY)); // -7 assumed request_key() authorisation key

  /* Destination keyring identifier for KEYCTL_SET_REQKEY_KEYRING */

  scm_c_define("KEY_REQKEY_DEFL_NO_CHANGE", scm_from_signed_integer(KEY_REQKEY_DEFL_NO_CHANGE ));  // -1 No change
  scm_c_define("KEY_REQKEY_DEFL_DEFAULT", scm_from_signed_integer(KEY_REQKEY_DEFL_DEFAULT ));  // 0 Default[1]
  scm_c_define("KEY_REQKEY_DEFL_THREAD_KEYRING", scm_from_signed_integer(KEY_REQKEY_DEFL_THREAD_KEYRING ));  // 1 Thread keyring
  scm_c_define("KEY_REQKEY_DEFL_PROCESS_KEYRING", scm_from_signed_integer(KEY_REQKEY_DEFL_PROCESS_KEYRING ));  // 2 Process keyring
  scm_c_define("KEY_REQKEY_DEFL_SESSION_KEYRING", scm_from_signed_integer(KEY_REQKEY_DEFL_SESSION_KEYRING ));  // 3 Session keyring
  scm_c_define("KEY_REQKEY_DEFL_USER_KEYRING", scm_from_signed_integer(KEY_REQKEY_DEFL_USER_KEYRING )); // 4 User keyring
  scm_c_define("KEY_REQKEY_DEFL_USER_SESSION_KEYRING", scm_from_signed_integer(KEY_REQKEY_DEFL_USER_SESSION_KEYRING)); // 5 User session keyring
  scm_c_define("KEY_REQKEY_DEFL_GROUP_KEYRING", scm_from_signed_integer(KEY_REQKEY_DEFL_GROUP_KEYRING )); // 6 Group keyring
 
  /* Add and request keys */

  scm_c_define_gsubr ("add-key", 2, 2, 0, add_key_wrapper);  

  scm_c_define_gsubr ("request-key", 2, 2, 0, request_key_wrapper);

  /* keyctl methods.
     Separated out to procedures 'cause that's probably a good idea.
   */

  // key_serial_t keyctl(KEYCTL_GET_KEYRING_ID, key_serial_t id, int create);
  scm_c_define_gsubr ("keyctl-get-keyring-id", 1, 1, 0, keyctl_get_keyring_ID_wrapper);

  // key_serial_t keyctl(KEYCTL_JOIN_SESSION_KEYRING, const char *name);
  scm_c_define_gsubr ("keyctl-join-session-keyring", 0, 1, 0, keyctl_join_session_keyring_wrapper);

  // long keyctl(KEYCTL_UPDATE, key_serial_t key, const void *payload, size_t plen);
  scm_c_define_gsubr ("keyctl-update", 1, 1, 0, keyctl_update_wrapper);

  // long keyctl(KEYCTL_REVOKE, key_serial_t key);
  scm_c_define_gsubr ("keyctl-revoke", 1, 0, 0, keyctl_revoke_wrapper);

  // long keyctl(KEYCTL_CHOWN, key_serial_t key, uid_t uid, gid_t gid);
  scm_c_define_gsubr ("keyctl-chown", 1, 2, 0, keyctl_chown_wrapper);

  // long keyctl(KEYCTL_SETPERM, key_serial_t key, key_perm_t perm);
  scm_c_define_gsubr ("keyctl-setperm", 2, 0, 0, keyctl_setperm_wrapper);

  // long keyctl(KEYCTL_DESCRIBE, key_serial_t key, char *buffer, size_t buflen);
  scm_c_define_gsubr ("keyctl-describe", 1, 0, 0, keyctl_describe_wrapper);
  
  // long keyctl(KEYCTL_CLEAR, key_serial_t keyring);
  scm_c_define_gsubr ("keyctl-clear", 1, 0, 0, keyctl_clear_wrapper);

  // long keyctl(KEYCTL_LINK, key_serial_t keyring, key_serial_t key);
  scm_c_define_gsubr ("keyctl-link", 2, 0, 0, keyctl_link_wrapper);

  // long keyctl(KEYCTL_UNLINK, key_serial_t keyring, key_serial_t key);
  scm_c_define_gsubr ("keyctl-unlink", 2, 0, 0, keyctl_unlink_wrapper);

  // key_serial_t keyctl(KEYCTL_SEARCH, key_serial_t keyring,  const char *type, const char *description,  key_serial_t dest_keyring);
  scm_c_define_gsubr ("keyctl-search", 3, 1, 0, keyctl_search_wrapper);

  // long keyctl(KEYCTL_READ, key_serial_t keyring, char *buffer, size_t buflen);
  scm_c_define_gsubr ("keyctl-read", 1, 0, 0, keyctl_read_wrapper);

  // long keyctl(KEYCTL_INSTANTIATE, key_serial_t key, const void *payload, size_t plen, key_serial_t keyring);
  scm_c_define_gsubr ("keyctl-instantiate", 2, 1, 0, keyctl_instantiate_wrapper);

  // long keyctl(KEYCTL_NEGATE, key_serial_t key, unsigned timeout, key_serial_t keyring);
  scm_c_define_gsubr ("keyctl-negate", 2, 1, 0, keyctl_negate_wrapper);

  // long keyctl(KEYCTL_REJECT, key_serial_t key, unsigned timeout, unsigned error, key_serial_t keyring);
  scm_c_define_gsubr ("keyctl-reject", 3, 1, 0, keyctl_reject_wrapper);

  // long keyctl(KEYCTL_SET_REQKEY_KEYRING, int reqkey_defl);
  scm_c_define_gsubr ("keyctl-set-reqkey-keyring", 1, 0, 0, keyctl_set_reqkey_keyring_wrapper);

  // long keyctl(KEYCTL_SET_TIMEOUT, key_serial_t key, unsigned timeout);
  scm_c_define_gsubr ("keyctl-set-timeout", 2, 0, 0, keyctl_set_timeout_wrapper);

  // long keyctl(KEYCTL_ASSUME_AUTHORITY, key_serial_t key);
  scm_c_define_gsubr ("keyctl-assume-authority", 0, 1, 0, keyctl_assume_authority_wrapper);
 
  // long keyctl(KEYCTL_GET_SECURITY, key_serial_t key, char *buffer, size_t buflen)
  scm_c_define_gsubr ("keyctl-get-security", 1, 0, 0, keyctl_get_security_wrapper);

  // long keyctl(KEYCTL_SESSION_TO_PARENT); 
  scm_c_define_gsubr ("keyctl-session-to-parent", 0, 0, 0, keyctl_session_to_parent_wrapper);

  // long keyctl(KEYCTL_INVALIDATE, key_serial_t key);
  scm_c_define_gsubr ("keyctl-invalidate", 1, 0, 0, keyctl_invalidate_wrapper);


  /* Permission bits */

  //scm_c_define("KEY_SPEC_THREAD_KEYRING", scm_from_signed_integer(KEY_SPEC_THREAD_KEYRING)); // -1 thread-specific keyring

  scm_c_define("KEY_POS_VIEW", scm_from_uint32(KEY_POS_VIEW)); //	0x01000000	/* possessor can view a key's attributes */
  scm_c_define("KEY_POS_READ", scm_from_uint32(KEY_POS_READ)); //	0x02000000	/* possessor can read key payload / view keyring */
  scm_c_define("KEY_POS_WRITE", scm_from_uint32(KEY_POS_WRITE)); //	0x04000000	/* possessor can update key payload / add link to keyring */
  scm_c_define("KEY_POS_SEARCH", scm_from_uint32(KEY_POS_SEARCH)); //	0x08000000	/* possessor can find a key in search / search a keyring */
  scm_c_define("KEY_POS_LINK", scm_from_uint32(KEY_POS_LINK)); //	0x10000000	/* possessor can create a link to a key/keyring */
  scm_c_define("KEY_POS_SETATTR", scm_from_uint32(KEY_POS_SETATTR)); //	0x20000000	/* possessor can set key attributes */
  scm_c_define("KEY_POS_ALL", scm_from_uint32(KEY_POS_ALL)); //	        0x3f000000

  scm_c_define("KEY_USR_VIEW", scm_from_uint32(KEY_USR_VIEW)); //	0x00010000	/* user permissions... */
  scm_c_define("KEY_USR_READ", scm_from_uint32(KEY_USR_READ)); //	0x00020000
  scm_c_define("KEY_USR_WRITE", scm_from_uint32(KEY_USR_WRITE)); //	0x00040000
  scm_c_define("KEY_USR_SEARCH", scm_from_uint32(KEY_USR_SEARCH)); //	0x00080000
  scm_c_define("KEY_USR_LINK", scm_from_uint32(KEY_USR_LINK)); //	0x00100000
  scm_c_define("KEY_USR_SETATTR", scm_from_uint32(KEY_USR_SETATTR)); //	0x00200000
  scm_c_define("KEY_USR_ALL", scm_from_uint32(KEY_USR_ALL)); //	        0x003f0000

  scm_c_define("KEY_GRP_VIEW", scm_from_uint32(KEY_GRP_VIEW)); //	0x00000100	/* group permissions... */
  scm_c_define("KEY_GRP_READ", scm_from_uint32(KEY_GRP_READ)); //	0x00000200
  scm_c_define("KEY_GRP_WRITE", scm_from_uint32(KEY_GRP_WRITE)); //	0x00000400
  scm_c_define("KEY_GRP_SEARCH", scm_from_uint32(KEY_GRP_SEARCH)); //	0x00000800
  scm_c_define("KEY_GRP_LINK", scm_from_uint32(KEY_GRP_LINK)); //	0x00001000
  scm_c_define("KEY_GRP_SETATTR", scm_from_uint32(KEY_GRP_SETATTR)); //	0x00002000
  scm_c_define("KEY_GRP_ALL", scm_from_uint32(KEY_GRP_ALL)); //	        0x00003f00

  scm_c_define("KEY_OTH_VIEW", scm_from_uint32(KEY_OTH_VIEW)); //	0x00000001	/* third party permissions... */
  scm_c_define("KEY_OTH_READ", scm_from_uint32(KEY_OTH_READ)); //	0x00000002
  scm_c_define("KEY_OTH_WRITE", scm_from_uint32(KEY_OTH_WRITE)); //	0x00000004
  scm_c_define("KEY_OTH_SEARCH", scm_from_uint32(KEY_OTH_SEARCH)); //	0x00000008
  scm_c_define("KEY_OTH_LINK", scm_from_uint32(KEY_OTH_LINK)); //	0x00000010
  scm_c_define("KEY_OTH_SETATTR", scm_from_uint32(KEY_OTH_SETATTR)); //	0x00000010
  scm_c_define("KEY_OTH_ALL", scm_from_uint32(KEY_OTH_ALL)); //	        0x0000003f

  /* Library constants */
  scm_c_define("keyutils_version_string", scm_from_locale_string(keyutils_version_string));
  scm_c_define("keyutils_build_string", scm_from_locale_string(keyutils_build_string));

}
