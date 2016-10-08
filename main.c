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
#define STRING_DESC "STRING"
#define BOOL_DESC "BOOL"
#define OR_FALSE " or #f"

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

/* SCM */
SCM_DEFINE (add_key_wrapper,   /* Function name in C */
            "add-key", /* Function name in Scheme */
            2, 2,      /* No. of required/optional args */
            0,         /* Whether accepts "rest" arg */
            (SCM keytype, SCM description, SCM payload, SCM keyring), /* C argument list */
            "Add a key.") /* Docstring */
{
  key_serial_t result = 0;

  char *req_keytype = NULL;
  char *req_description = NULL;

  void * req_payload = NULL;
  size_t req_plen = 0;
  
  key_serial_t req_keyring = 0;

  SCM_ASSERT_TYPE(scm_is_string(keytype), keytype, SCM_ARG1, s_add_key_wrapper, STRING_DESC );
  SCM_ASSERT_TYPE(scm_is_string(description), description, SCM_ARG2, s_add_key_wrapper, STRING_DESC );
  SCM_ASSERT_TYPE(scm_is_string(payload) 
		  || scm_is_false(payload)
		  || scm_is_undefined(payload),
		  payload, SCM_ARG3, s_add_key_wrapper, STRING_DESC OR_FALSE );
  SCM_ASSERT_TYPE(scm_is_key_serial_t(keyring)
		  || scm_is_undefined(keyring), 
		  keyring, SCM_ARG4, s_add_key_wrapper, KEY_SERIAL_DESC );

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
      scm_syserror(s_add_key_wrapper);
    }

  return scm_from_key_serial_t(result);
}


/* SCM */
SCM_DEFINE(request_key_wrapper,
	   "request-key",
	   2, 2,
	   0, 
	   (SCM keytype, SCM description, SCM callout_info, SCM dest_keyring),
	   "Request a key.")
{
  key_serial_t result = 0;

  char *req_keytype = NULL;
  char *req_description = NULL;
  void *req_callout_info = NULL;
  key_serial_t req_dest_keyring = 0;

  SCM_ASSERT_TYPE(scm_is_string(keytype), keytype, SCM_ARG1, s_request_key_wrapper, STRING_DESC );
  SCM_ASSERT_TYPE(scm_is_string(description), description, SCM_ARG2, s_request_key_wrapper, STRING_DESC );
  SCM_ASSERT_TYPE(scm_is_string(callout_info)
		  || scm_is_false(callout_info)
		  || scm_is_undefined(callout_info), 
		  keytype, SCM_ARG3, s_request_key_wrapper, STRING_DESC OR_FALSE );
  SCM_ASSERT_TYPE(scm_is_key_serial_t(dest_keyring)
		  || scm_is_false(dest_keyring)
		  || scm_is_undefined(dest_keyring), 
		  keytype, SCM_ARG4, s_request_key_wrapper, KEY_SERIAL_DESC OR_FALSE );

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
    scm_syserror(s_request_key_wrapper);
  }

  return scm_from_key_serial_t(result);

}



// key_serial_t keyctl(KEYCTL_GET_KEYRING_ID, key_serial_t id, int create);
/* SCM */
SCM_DEFINE (keyctl_get_keyring_ID_wrapper,   /* Function name in C */
            "keyctl-get-keyring-id", /* Function name in Scheme */
            1, 1,      /* No. of required/optional args */
            0,         /* Whether accepts "rest" arg */
            (SCM id, SCM create), /* C argument list */
            "Get the ID of a keyring.") /* Docstring */

{
  key_serial_t result = 0;

  key_serial_t req_id = 0;
  int req_create = 0;
  
  SCM_ASSERT_TYPE(scm_is_key_serial_t(id), id, SCM_ARG1, s_keyctl_get_keyring_ID_wrapper, KEY_SERIAL_DESC );
  SCM_ASSERT_TYPE(scm_is_bool(create)
		  || scm_is_undefined(create), 
		  create, SCM_ARG2, s_keyctl_get_keyring_ID_wrapper, BOOL_DESC);
  
  req_id = scm_to_key_serial_t(id);

  if(scm_is_bool(create))
    {
      req_create = scm_to_bool(create);
    }

  result = keyctl(KEYCTL_GET_KEYRING_ID, req_id, req_create);
  
  if(result < 0) //ENOKEY
    {
      scm_syserror(s_keyctl_get_keyring_ID_wrapper);
    }

  return scm_from_key_serial_t(result);
}

// key_serial_t keyctl(KEYCTL_JOIN_SESSION_KEYRING, const char *name);
/* SCM */
SCM_DEFINE (keyctl_join_session_keyring_wrapper,   /* Function name in C */
            "keyctl-join-session-keyring", /* Function name in Scheme */
            0, 1,      /* No. of required/optional args */
            0,         /* Whether accepts "rest" arg */
            (SCM name), /* C argument list */
            "Join session keyring.") /* Docstring */
{
  key_serial_t result = 0;
  char *req_name = NULL;
  
  SCM_ASSERT_TYPE(scm_is_string(name) 
		  || scm_is_false(name)
		  || scm_is_undefined(name), 
		  name, SCM_ARG1, s_keyctl_join_session_keyring_wrapper, STRING_DESC OR_FALSE);
  
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
      scm_syserror(s_keyctl_join_session_keyring_wrapper);
    }

  return scm_from_key_serial_t(result);
}


// long keyctl(KEYCTL_UPDATE, key_serial_t key, const void *payload, size_t plen);
/* SCM */
SCM_DEFINE (keyctl_update_wrapper,   /* Function name in C */
            "keyctl-update", /* Function name in Scheme */
            1, 1,      /* No. of required/optional args */
            0,         /* Whether accepts "rest" arg */
            (SCM key, SCM payload), /* C argument list */
            "Update a key's payload") /* Docstring */
{
  long result = 0;

  key_serial_t req_key = 0;

  void * req_payload = NULL;
  size_t req_plen = 0;
  
  SCM_ASSERT_TYPE(scm_is_key_serial_t(key), key, SCM_ARG1, s_keyctl_update_wrapper, KEY_SERIAL_DESC );
  SCM_ASSERT_TYPE(scm_is_string(payload)
		  || scm_is_false(payload)
		  || scm_is_undefined(payload), 
		  payload, SCM_ARG2, s_keyctl_update_wrapper, STRING_DESC );
  
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
      scm_syserror(s_keyctl_update_wrapper);
    }

  return scm_from_long(result);
}

// long keyctl(KEYCTL_REVOKE, key_serial_t key);
/* SCM */
SCM_DEFINE (keyctl_revoke_wrapper,   /* Function name in C */
            "keyctl-revoke", /* Function name in Scheme */
            1, 0,      /* No. of required/optional args */
            0,         /* Whether accepts "rest" arg */
            (SCM key), /* C argument list */
            "Revoke a key.") /* Docstring */
{ 
  long result;
  
  key_serial_t req_key = 0;

  SCM_ASSERT_TYPE(scm_is_key_serial_t(key), key, SCM_ARG1, s_keyctl_revoke_wrapper, KEY_SERIAL_DESC);
  
  req_key = scm_to_key_serial_t(key);

  result = keyctl(KEYCTL_REVOKE, req_key);
  
  if(result < 0)
    {
      scm_syserror(s_keyctl_revoke_wrapper);
    }

  return result == 0 ? SCM_BOOL_T : scm_from_long(result);
}


// long keyctl(KEYCTL_CHOWN, key_serial_t key, uid_t uid, gid_t gid);
/* SCM */
SCM_DEFINE (keyctl_chown_wrapper,   /* Function name in C */
            "keyctl-chown", /* Function name in Scheme */
            1, 2,      /* No. of required/optional args */
            0,         /* Whether accepts "rest" arg */
            (SCM key, SCM uid, SCM gid), /* C argument list */
            "Set a key's uid and gid.") /* Docstring */
{
  long result = 0;
  key_serial_t req_key = 0;
  uid_t req_uid = -1;
  gid_t req_gid = -1;

  SCM_ASSERT_TYPE(scm_is_key_serial_t(key), key, SCM_ARG1, s_keyctl_chown_wrapper, KEY_SERIAL_DESC);
  SCM_ASSERT_TYPE(scm_is_number(uid) 
		  || scm_is_false(uid) 
		  || scm_is_undefined(uid),
		  uid, SCM_ARG2, s_keyctl_chown_wrapper, KEY_SERIAL_DESC OR_FALSE);
  SCM_ASSERT_TYPE(scm_is_number(gid)
		  || scm_is_false(gid)
		  || scm_is_undefined(gid),
		  gid, SCM_ARG3, s_keyctl_chown_wrapper, KEY_SERIAL_DESC OR_FALSE);

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
      scm_syserror(s_keyctl_chown_wrapper);
    }

  return scm_from_long(result);
}


// long keyctl(KEYCTL_SETPERM, key_serial_t key, key_perm_t perm);
/* SCM */
SCM_DEFINE (keyctl_setperm_wrapper,   /* Function name in C */
            "keyctl-setperm", /* Function name in Scheme */
            2, 0,      /* No. of required/optional args */
            0,         /* Whether accepts "rest" arg */
            (SCM key, SCM perm), /* C argument list */
            "Set a key's permissions.") /* Docstring */
{
  long result = 0;
  key_serial_t req_key = 0;
  key_perm_t req_perm = 0;

  SCM_ASSERT_TYPE(scm_is_key_serial_t(key), key, SCM_ARG1, s_keyctl_setperm_wrapper, KEY_SERIAL_DESC);
  SCM_ASSERT_TYPE(scm_is_number(perm), perm, SCM_ARG2, s_keyctl_setperm_wrapper, KEY_SERIAL_DESC);

  req_key = scm_to_key_serial_t(key);

  req_perm = (key_perm_t)scm_to_uint32(perm);

  result = keyctl(KEYCTL_SETPERM, req_key, req_perm);

  if(result < 0)
    {
      scm_syserror(s_keyctl_setperm_wrapper);
    }

  return scm_from_long(result);
}


// long keyctl(KEYCTL_DESCRIBE, key_serial_t key, char *buffer, size_t buflen);
/* SCM */
SCM_DEFINE (keyctl_describe_wrapper,   /* Function name in C */
            "keyctl-describe", /* Function name in Scheme */
            1, 0,      /* No. of required/optional args */
            0,         /* Whether accepts "rest" arg */
            (SCM key), /* C argument list */
            "Describe a key.") /* Docstring */
{
  long result = 0;

  key_serial_t req_key = 0;
  char req_buffer[256];

  SCM_ASSERT_TYPE(scm_is_key_serial_t(key), key, SCM_ARG1, s_keyctl_describe_wrapper, KEY_SERIAL_DESC);

  req_key = scm_to_key_serial_t(key);

  result = keyctl(KEYCTL_DESCRIBE, req_key, req_buffer, 256);

  if(result < 0)
    {
      scm_syserror(s_keyctl_describe_wrapper);
    }

  result = result > 256 ? 256 : result;

  // Remove final zero.
  return scm_from_locale_stringn(req_buffer, result - 1);
}


// long keyctl(KEYCTL_CLEAR, key_serial_t keyring);
/* SCM */
SCM_DEFINE (keyctl_clear_wrapper,   /* Function name in C */
            "keyctl-clear", /* Function name in Scheme */
            1, 0,      /* No. of required/optional args */
            0,         /* Whether accepts "rest" arg */
            (SCM keyring), /* C argument list */
            "Clear a keyring.") /* Docstring */
{
  long result = 0;

  key_serial_t req_keyring = 0;
  
  SCM_ASSERT_TYPE(scm_is_key_serial_t(keyring), keyring, SCM_ARG1, s_keyctl_clear_wrapper, KEY_SERIAL_DESC);
  
  req_keyring = scm_to_key_serial_t(keyring);

  result = keyctl(KEYCTL_CLEAR, req_keyring);

  if(result < 0)
    {
      scm_syserror(s_keyctl_clear_wrapper);
    }
  
  return SCM_BOOL_T;
}



// long keyctl(KEYCTL_LINK, key_serial_t keyring, key_serial_t key);
/* SCM */
SCM_DEFINE (keyctl_link_wrapper,   /* Function name in C */
            "keyctl-link", /* Function name in Scheme */
            2, 0,      /* No. of required/optional args */
            0,         /* Whether accepts "rest" arg */
            (SCM keyring, SCM key), /* C argument list */
            "Link a key to a keyring.") /* Docstring */
{
  long result = 0;
  key_serial_t req_keyring = 0;
  key_serial_t req_key = 0;

  SCM_ASSERT_TYPE(scm_is_key_serial_t(keyring), keyring, SCM_ARG1, s_keyctl_link_wrapper, KEY_SERIAL_DESC);
  SCM_ASSERT_TYPE(scm_is_key_serial_t(key), key, SCM_ARG2, s_keyctl_link_wrapper, KEY_SERIAL_DESC);

  req_keyring = scm_to_key_serial_t(keyring);

  req_key = scm_to_key_serial_t(key);

  result = keyctl(KEYCTL_LINK, req_keyring, req_key);

  if(result < 0)
    {
      scm_syserror(s_keyctl_link_wrapper);
    }
  
  return result ? scm_from_long(result) : SCM_BOOL_T;
}


// long keyctl(KEYCTL_UNLINK, key_serial_t keyring, key_serial_t key);
/* SCM */
SCM_DEFINE (keyctl_unlink_wrapper,   /* Function name in C */
            "keyctl-unlink", /* Function name in Scheme */
            2, 0,      /* No. of required/optional args */
            0,         /* Whether accepts "rest" arg */
            (SCM keyring, SCM key), /* C argument list */
            "Unlink a key.") /* Docstring */
{
  long result = 0;
  key_serial_t req_keyring = 0;
  key_serial_t req_key = 0;

  SCM_ASSERT_TYPE(scm_is_key_serial_t(keyring), keyring, SCM_ARG1, s_keyctl_unlink_wrapper, KEY_SERIAL_DESC);
  SCM_ASSERT_TYPE(scm_is_key_serial_t(key), key, SCM_ARG2, s_keyctl_unlink_wrapper, KEY_SERIAL_DESC);

  req_keyring = scm_to_key_serial_t(keyring);

  req_key = scm_to_key_serial_t(key);

  result = keyctl(KEYCTL_UNLINK, req_keyring, req_key);

  if(result < 0)
    {
      scm_syserror(s_keyctl_unlink_wrapper);
    }
  
  return result ? scm_from_long(result) : SCM_BOOL_T;
}



// key_serial_t keyctl(KEYCTL_SEARCH, key_serial_t keyring,  const char *type, const char *description,  key_serial_t dest_keyring);
/* SCM */
SCM_DEFINE (keyctl_search_wrapper,   /* Function name in C */
            "keyctl-search", /* Function name in Scheme */
            3, 1,      /* No. of required/optional args */
            0,         /* Whether accepts "rest" arg */
            (SCM keyring, SCM keytype, SCM description, SCM dest_keyring), /* C argument list */
            "Search for a key by description.") /* Docstring */
{
  key_serial_t result = 0;
  key_serial_t req_keyring = 0;
  char * req_keytype = NULL;
  char * req_description = NULL;
  key_serial_t req_dest_keyring = 0;

  SCM_ASSERT_TYPE(scm_is_key_serial_t(keyring), keyring, SCM_ARG1, s_keyctl_search_wrapper, KEY_SERIAL_DESC);
  SCM_ASSERT_TYPE(scm_is_string(keytype), keytype, SCM_ARG2, s_keyctl_search_wrapper, STRING_DESC);
  SCM_ASSERT_TYPE(scm_is_string(description), description, SCM_ARG3, s_keyctl_search_wrapper, STRING_DESC);
  SCM_ASSERT_TYPE(scm_is_key_serial_t(dest_keyring) 
		  || scm_is_false(dest_keyring)
		  || scm_is_undefined(dest_keyring), 
		  dest_keyring, SCM_ARG4, s_keyctl_search_wrapper, KEY_SERIAL_DESC);
  
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
      scm_syserror(s_keyctl_search_wrapper);
    }

  return result ? scm_from_key_serial_t(result) : SCM_BOOL_T;
}


// long keyctl(KEYCTL_READ, key_serial_t keyring, char *buffer, size_t buflen);
/* SCM */
SCM_DEFINE (keyctl_read_wrapper,   /* Function name in C */
            "keyctl-read", /* Function name in Scheme */
            1, 0,      /* No. of required/optional args */
            0,         /* Whether accepts "rest" arg */
            (SCM key), /* C argument list */
            "Read a key.") /* Docstring */
{
  long result = 0;

  key_serial_t req_key = 0;
  char req_buffer[256];
  
  SCM_ASSERT_TYPE(scm_is_key_serial_t(key), key, SCM_ARG1, s_keyctl_read_wrapper, KEY_SERIAL_DESC);

  req_key = scm_to_key_serial_t(key);

  result = keyctl(KEYCTL_READ, req_key, req_buffer, 256);

  if(result < 0)
    {
      scm_syserror(s_keyctl_read_wrapper);
    }

  result = result > 256 ? 256 : result;

  return result ? scm_from_locale_stringn(req_buffer, result) : SCM_BOOL_F;
}



// long keyctl(KEYCTL_INSTANTIATE, key_serial_t key, const void *payload, size_t plen, key_serial_t keyring);
/* SCM */
SCM_DEFINE (keyctl_instantiate_wrapper,   /* Function name in C */
            "keyctl-instantiate", /* Function name in Scheme */
            2, 1,      /* No. of required/optional args */
            0,         /* Whether accepts "rest" arg */
            (SCM key, SCM payload, SCM keyring), /* C argument list */
            "Instantiate a requested key.") /* Docstring */
{
  long result = 0;

  key_serial_t req_key = 0;
  key_serial_t req_keyring = 0;

  void * req_payload = NULL;
  size_t req_plen = 0;

  SCM_ASSERT_TYPE(scm_is_key_serial_t(key), key, SCM_ARG1, s_keyctl_instantiate_wrapper, KEY_SERIAL_DESC);
  SCM_ASSERT_TYPE(scm_is_string(payload), payload, SCM_ARG2, s_keyctl_instantiate_wrapper, STRING_DESC);
  SCM_ASSERT_TYPE(scm_is_key_serial_t(keyring)
	     || scm_is_false(keyring)
	     || scm_is_undefined(keyring),
	     keyring, SCM_ARG3, s_keyctl_instantiate_wrapper, KEY_SERIAL_DESC OR_FALSE );


  scm_dynwind_begin(0);

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

  result = keyctl(KEYCTL_INSTANTIATE,
		  req_key,
		  req_payload,
		  req_plen,
		  req_keyring);

  scm_dynwind_end();

  if(result < 0)
    {
      scm_syserror(s_keyctl_instantiate_wrapper);
    }
  
  return scm_from_key_serial_t(result);
}


// long keyctl(KEYCTL_NEGATE, key_serial_t key, unsigned timeout, key_serial_t keyring);
/* SCM */
SCM_DEFINE (keyctl_negate_wrapper,   /* Function name in C */
            "keyctl-negate", /* Function name in Scheme */
            2, 1,      /* No. of required/optional args */
            0,         /* Whether accepts "rest" arg */
            (SCM key, SCM timeout, SCM keyring), /* C argument list */
            "Negate a key.") /* Docstring */
{
  long result = 0;

  key_serial_t req_key = 0;
  unsigned req_timeout = 0;
  key_serial_t req_keyring = 0;

  SCM_ASSERT_TYPE(scm_is_key_serial_t(key), key, SCM_ARG1, s_keyctl_negate_wrapper, KEY_SERIAL_DESC );  
  SCM_ASSERT_TYPE(scm_is_number(timeout), timeout, SCM_ARG2, s_keyctl_negate_wrapper, KEY_SERIAL_DESC );
  SCM_ASSERT_TYPE(scm_is_key_serial_t(keyring) 
		  || scm_is_false(keyring)
		  || scm_is_undefined(keyring), 
		  keyring, SCM_ARG3, s_keyctl_negate_wrapper, KEY_SERIAL_DESC OR_FALSE );  

  req_key = scm_to_key_serial_t(key);

  req_timeout = scm_to_unsigned_integer(timeout, 0, INT_MAX);

  if(scm_is_key_serial_t(keyring))
    {
      req_keyring = scm_to_key_serial_t(keyring);
    }

  result = keyctl(KEYCTL_NEGATE, req_key, req_timeout, req_keyring);

  if(result < 0)
    {
      scm_syserror(s_keyctl_negate_wrapper);
    }

  // What does this result mean?
  return scm_from_long(result);
}


// long keyctl(KEYCTL_REJECT, key_serial_t key, unsigned timeout, unsigned error, key_serial_t keyring);
/* SCM */
SCM_DEFINE (keyctl_reject_wrapper,   /* Function name in C */
            "keyctl-reject", /* Function name in Scheme */
            3, 1,      /* No. of required/optional args */
            0,         /* Whether accepts "rest" arg */
            (SCM key, SCM timeout, SCM error, SCM keyring), /* C argument list */
            "Rejects a key.") /* Docstring */
{
  long result = 0;

  key_serial_t req_key = 0;
  unsigned req_timeout = 0;
  unsigned req_error = 0;
  key_serial_t req_keyring = 0;

  SCM_ASSERT_TYPE(scm_is_key_serial_t(key), key, SCM_ARG1, s_keyctl_reject_wrapper, KEY_SERIAL_DESC );  
  SCM_ASSERT_TYPE(scm_is_number(timeout), timeout, SCM_ARG2, s_keyctl_reject_wrapper, KEY_SERIAL_DESC );
  SCM_ASSERT_TYPE(scm_is_number(error), error, SCM_ARG3, s_keyctl_reject_wrapper, KEY_SERIAL_DESC );
  SCM_ASSERT_TYPE(scm_is_key_serial_t(keyring) 
		  || scm_is_false(keyring)
		  || scm_is_undefined(keyring), 
		  keyring, SCM_ARG4, s_keyctl_reject_wrapper, KEY_SERIAL_DESC OR_FALSE );  

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
      scm_syserror(s_keyctl_reject_wrapper);
    }

  return scm_from_long(result);
}


// long keyctl(KEYCTL_SET_REQKEY_KEYRING, int reqkey_defl);
/* SCM */
SCM_DEFINE (keyctl_set_reqkey_keyring_wrapper,   /* Function name in C */
            "keyctl-set-reqkey-keyring", /* Function name in Scheme */
            1, 0,      /* No. of required/optional args */
            0,         /* Whether accepts "rest" arg */
            (SCM reqkey_defl), /* C argument list */
            "Sets a requested key's keyring.") /* Docstring */
{
  long result = 0;

  int req_reqkey_defl = 0;

  SCM_ASSERT_TYPE(scm_is_signed_integer(reqkey_defl, INT_MIN, INT_MAX), 
		  reqkey_defl, SCM_ARG1, s_keyctl_set_reqkey_keyring_wrapper, KEY_SERIAL_DESC );

  req_reqkey_defl = scm_to_signed_integer(reqkey_defl, INT_MIN, INT_MAX);

  result = keyctl(KEYCTL_SET_REQKEY_KEYRING, req_reqkey_defl);

  if(result < 0)
    {
      scm_syserror(s_keyctl_set_reqkey_keyring_wrapper);
    }

  return scm_from_long(result);
}


// long keyctl(KEYCTL_SET_TIMEOUT, key_serial_t key, unsigned timeout);
/* SCM */
SCM_DEFINE (keyctl_set_timeout_wrapper,   /* Function name in C */
            "keyctl-set-timeout", /* Function name in Scheme */
            2, 0,      /* No. of required/optional args */
            0,         /* Whether accepts "rest" arg */
            (SCM key, SCM timeout), /* C argument list */
            "Sets a key's timeout.") /* Docstring */
{
  long result = 0;

  key_serial_t req_key = 0;
  /* KEYCTL_SET_TIMEOUT parameter is unsigned implied int. */
  unsigned req_timeout = 0;

  SCM_ASSERT_TYPE(scm_is_key_serial_t(key), key, SCM_ARG1, s_keyctl_set_timeout_wrapper, KEY_SERIAL_DESC );  
  SCM_ASSERT_TYPE(scm_is_unsigned_integer(timeout, 0, INT_MAX), timeout, SCM_ARG2, s_keyctl_set_timeout_wrapper, KEY_SERIAL_DESC );

  req_key = scm_to_key_serial_t(key);

  req_timeout = scm_to_unsigned_integer(timeout, 0, INT_MAX); // TODO: check range.

  result = keyctl(KEYCTL_SET_TIMEOUT, req_key, req_timeout); 
   
  if(result < 0)
    {
      scm_syserror(s_keyctl_set_timeout_wrapper);
    }

  return result ? scm_from_long(result) : SCM_BOOL_T;
}


// long keyctl(KEYCTL_ASSUME_AUTHORITY, key_serial_t key);
/* SCM */
SCM_DEFINE (keyctl_assume_authority_wrapper,   /* Function name in C */
            "keyctl-assume-authority", /* Function name in Scheme */
            0, 1,      /* No. of required/optional args */
            0,         /* Whether accepts "rest" arg */
            (SCM key), /* C argument list */
            "Assumes authority over a key.") /* Docstring */
{
  long result = 0;

  key_serial_t req_key = 0;

  SCM_ASSERT_TYPE(scm_is_key_serial_t(key)
		  || scm_is_false(key)
		  || scm_is_undefined(key), 
		  key, SCM_ARG1, s_keyctl_assume_authority_wrapper, KEY_SERIAL_DESC );  
  
  if(scm_is_key_serial_t(key))
    {
      req_key = scm_to_key_serial_t(key);
    }

  result = keyctl(KEYCTL_ASSUME_AUTHORITY, req_key);

  if(result < 0)
    {
      scm_syserror(s_keyctl_assume_authority_wrapper);
    }
  
  return result ? scm_from_long(result) : SCM_BOOL_T ;
}


// long keyctl(KEYCTL_GET_SECURITY, key_serial_t key, char *buffer, size_t buflen)
/* SCM */
SCM_DEFINE (keyctl_get_security_wrapper,   /* Function name in C */
            "keyctl-get-security", /* Function name in Scheme */
            1, 0,      /* No. of required/optional args */
            0,         /* Whether accepts "rest" arg */
            (SCM key), /* C argument list */
            "Gets the security descriptor for a key.") /* Docstring */
{
  long result = 0;

  key_serial_t req_key = 0;
  char req_buffer[256];

  SCM_ASSERT_TYPE(scm_is_key_serial_t(key), key, SCM_ARG1, s_keyctl_get_security_wrapper, KEY_SERIAL_DESC);

  req_key = scm_to_key_serial_t(key);

  result = keyctl(KEYCTL_GET_SECURITY, req_key, req_buffer, 256);

  if(result < 0)
    {
      scm_syserror(s_keyctl_get_security_wrapper);
    }
  
  result = result > 256 ? 256 : result;

  // Remove final zero.
  return scm_from_locale_stringn(req_buffer, result - 1);
}


// long keyctl(KEYCTL_SESSION_TO_PARENT); 
/* SCM */
SCM_DEFINE (keyctl_session_to_parent_wrapper,   /* Function name in C */
            "keyctl-session-to-parent", /* Function name in Scheme */
            0, 0,      /* No. of required/optional args */
            0,         /* Whether accepts "rest" arg */
            (void), /* C argument list */
            "Map session keychain to parent.") /* Docstring */
{
  long result = 0;

  result = keyctl(KEYCTL_SESSION_TO_PARENT);

  if(result < 0)
    {
      scm_syserror(s_keyctl_session_to_parent_wrapper);
    }

  return result ? scm_from_long(result) : SCM_BOOL_T;
}


// long keyctl(KEYCTL_INVALIDATE, key_serial_t key);
/* SCM */
SCM_DEFINE (keyctl_invalidate_wrapper,   /* Function name in C */
            "keyctl-invalidate", /* Function name in Scheme */
            1, 0,      /* No. of required/optional args */
            0,         /* Whether accepts "rest" arg */
            (SCM key), /* C argument list */
            "Invalidate a key.") /* Docstring */
{
  long result = 0;
  key_serial_t req_key = 0;

  SCM_ASSERT_TYPE(scm_is_key_serial_t(key), key, SCM_ARG1, s_keyctl_invalidate_wrapper, KEY_SERIAL_DESC );

  req_key = scm_to_key_serial_t(key);

  result = keyctl(KEYCTL_INVALIDATE, req_key);

  if(result < 0)
    {
      scm_syserror(s_keyctl_invalidate_wrapper);
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

  #include "main.x"


  /* keyctl methods.
     Separated out to procedures 'cause that's probably a good idea.
   */


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
