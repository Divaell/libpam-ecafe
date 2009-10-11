/**
 * Copyright (C) 2009 Guillaume Viguier-Just
 * 
 * Author: Guillaume Viguier-Just <guillaume@wedus.org>
 * 
 * This file is part of pam_ecafe.
 * 
 * pam_ecafe is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * pam_ecafe is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with pam_ecafe.  If not, see <http://www.gnu.org/licenses/>.
 */

#define PAM_SM_AUTH

#include <stdio.h>
#include <stdlib.h>

#include <security/pam_modules.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>


int converse( pam_handle_t *pamh,
		int nargs,
		struct pam_message **message,
		struct pam_response **response  ) {
	int retval;
	struct pam_conv *conv;

	retval = pam_get_item(  pamh, PAM_CONV,  (const void **) &conv ) ;
	if ( retval == PAM_SUCCESS ) {
		retval = conv->conv(  nargs,  
				( const struct pam_message ** ) message,
				response, conv->appdata_ptr );
	}
	return retval;
}



/* From pam_unix/support.c */
int _set_auth_tok (  pam_handle_t *pamh,  
		int flags, int argc,
		const char **argv ) {
	int retval;
	char  *p;

	struct pam_message msg[1],*pmsg[1];
	struct pam_response *resp;

	/* set up conversation call */

	pmsg[0] = &msg[0];
	msg[0].msg_style = PAM_PROMPT_ECHO_OFF;
	msg[0].msg = "Password: ";
	resp = NULL;

	if ( ( retval = converse( pamh, 1 , pmsg, &resp ) ) != PAM_SUCCESS )
		return retval;

	if ( resp ) 
	{
		if ( ( flags & PAM_DISALLOW_NULL_AUTHTOK ) &&
				resp[0].resp == NULL )  
		{     
			free( resp );
			return PAM_AUTH_ERR;
		}   

		p = resp[ 0 ].resp;

		/* This could be a memory leak. If resp[0].resp
		   is malloc()ed, then it has to be free()ed!
		   -- alex  
		 */

		resp[ 0 ].resp = NULL;                

	} 
	else 
		return PAM_CONV_ERR;

	free( resp );
	pam_set_item( pamh, PAM_AUTHTOK, p );
	return PAM_SUCCESS;
}

/* Tests whether the given username is a timecode or not */
int is_timecode(const char *user) {
	if(user[0] == '0' ||
			user[0] == '1' ||
			user[0] == '2' ||
			user[0] == '3' ||
			user[0] == '4' ||
			user[0] == '5' ||
			user[0] == '6' ||
			user[0] == '7' ||
			user[0] == '8' ||
			user[0] == '9') {
		return 1;
	}
	else {
		return 0;
	}
}

/**
 * PAM Authentication function
 * Calls the daemon's connect_customer or connect_timecode method, depending on the authentication type
 */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *ph, int flags, int argc, const char **argv) {
	DBusGConnection *connection;
	GError *error;
	DBusGProxy *proxy;
	const char *user;
	char *password;
	int retval;
	int val = 0;
	char *strret;

	g_type_init ();

	error = NULL;
	connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, &error);
	if (connection == NULL) {
		g_error_free (error);
		return PAM_AUTHINFO_UNAVAIL;
	}

	/* Create a proxy object for the "bus driver" */

	proxy = dbus_g_proxy_new_for_name (connection,
			"org.ecafe.service",
			"/org/ecafe/daemon",
			"org.ecafe.interface");

	/* Get username */
	retval = pam_get_user(ph, &user, NULL);
	if (retval != PAM_SUCCESS)
		return retval;

	if(is_timecode(user) == 0) {
		/* Customer authentication */
		/* Get password */
		pam_get_item (ph, PAM_AUTHTOK, (void *) &password);

		if ( !password ) {
			retval = _set_auth_tok (ph, flags, argc, argv);

			if ( retval != PAM_SUCCESS ) {
				return retval;
			}
		}

		pam_get_item (ph, PAM_AUTHTOK, (void *) &password);

		if ( (retval = pam_get_item (ph, PAM_AUTHTOK, (void *)&password)) != PAM_SUCCESS) {
			return retval;
		}


		/* Call connect_customer method, wait for reply */
		error = NULL;
		if (!dbus_g_proxy_call (proxy, "connect_customer", &error, G_TYPE_STRING, user, 
					G_TYPE_STRING, password,
					G_TYPE_INVALID, G_TYPE_INT, &val, 
					G_TYPE_STRING, &strret,
					G_TYPE_INVALID))
		{
			g_error_free (error);
			g_object_unref (proxy);
			return PAM_AUTHINFO_UNAVAIL;
		}
	} else {
		/* Timecode authentication */
		/* Call connect_timecode method, and wait for reply */
		error = NULL;
		if (!dbus_g_proxy_call (proxy, "connect_timecode", &error, G_TYPE_STRING, user,
					G_TYPE_INVALID, G_TYPE_INT, &val, 
					G_TYPE_STRING, &strret,
					G_TYPE_INVALID))
		{
			g_error_free (error);
			g_object_unref (proxy);
			return PAM_AUTHINFO_UNAVAIL;
		}
		pam_set_item(ph, PAM_USER, "ecafe");
	}

	g_object_unref (proxy);

	/* Check the results */
	switch (val) {
		case 1:
			//Everything is fine
			return PAM_SUCCESS;
			break;
		case -3:
			// Client not found because the session Id was wrong
			return PAM_AUTHINFO_UNAVAIL;
			break;
		case -10:
			// already connected
			return PAM_AUTH_ERR;
			break;
		case -4:
			// Customer's login not found
			return PAM_USER_UNKNOWN;
			break;
		case -5:
			// Customer's password invalid
			return PAM_AUTH_ERR;
			break;
		case -6:
			// No time left (customer connection)
			return PAM_AUTH_ERR;
			break;
		case -7:
			// Timecode not found
			return PAM_USER_UNKNOWN;
			break;
		case -8:
			// Timecode is invalid
			return PAM_AUTH_ERR;
			break;
		case -9:
			// Timecode is associated with a customer account. Login with that account instead
			return PAM_AUTH_ERR;
			break;
		default:
			return PAM_AUTHINFO_UNAVAIL;
			break;
	}
}

/**
 * PAM set credentials function
 */
	PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char *argv[])
{
	return PAM_SUCCESS;
}

/**
 * PAM open session function
 */
	PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}

/**
 * PAM close session function
 * Calls the disconnect method of the daemon, to cleanly disconnect the daemon
 */
	PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	DBusGConnection *connection;
	GError *error;
	DBusGProxy *proxy;
	int val = 0;
	char *strret;

	g_type_init ();

	error = NULL;
	connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, &error);
	if (connection == NULL) {
		g_error_free (error);
		return PAM_SESSION_ERR;
	}

	/* Create a proxy object for the "bus driver" */

	proxy = dbus_g_proxy_new_for_name (connection,
			"org.ecafe.service",
			"/org/ecafe/daemon",
			"org.ecafe.interface");

	/* Call connect_customer method, wait for reply */
	error = NULL;
	if (!dbus_g_proxy_call (proxy, "disconnect", &error,	G_TYPE_INVALID, G_TYPE_INT, &val, 
				G_TYPE_STRING, &strret,
				G_TYPE_INVALID))
	{
		g_error_free (error);
		g_object_unref (proxy);
		return PAM_SESSION_ERR;
	}

	g_object_unref (proxy);

	switch(val) {
		case -3:
			return PAM_SESSION_ERR;
			break;
		case 1:
			return PAM_SUCCESS;
			break;
	}
}


