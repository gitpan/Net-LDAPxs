#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

/* LDAP C SDK Include Files */
#include <lber.h>
#include <ldap.h>

#include "const-c.inc"

/* Prototypes */
LDAP* _connect(char *, int, int, char *);
void ldap_add_mods(HV*, LDAPMod ***);
void free_attrs(LDAPMod **);
AV* get_entries(LDAP *, LDAPMessage *);

LDAP* 
_connect(char *host, int port, int version, char *scheme)
{
	int rc;
	LDAP* ld = NULL;
	char *ldapuri = NULL;

	LDAPURLDesc url;
	memset( &url, 0, sizeof(url));

	url.lud_scheme = scheme;
	url.lud_host = host;
	url.lud_port = port;
	url.lud_scope = LDAP_SCOPE_DEFAULT;
	ldapuri = ldap_url_desc2str( &url );

	rc = ldap_initialize( &ld, ldapuri );
	if (rc != LDAP_SUCCESS) {
		fprintf( stderr,
				"Could not create LDAP session handle for URI=%s (%d): %s\n",
				ldapuri, rc, ldap_err2string(rc) );
		exit( EXIT_FAILURE );
	}
	if (ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version) != LDAP_SUCCESS) {
		fprintf( stderr,
				"Could not set LDAP_OPT_PROTOCOL_VERSION %d\n",
				version );
		exit( EXIT_FAILURE );
	}
	return ld;
}

void
free_attrs(LDAPMod **list_of_attrs)
{
	int i = 0;
	while(list_of_attrs[i] != NULL)
		free(list_of_attrs[i++]->mod_values);
	free(list_of_attrs);
}

void
ldap_add_mods(HV* attrs_hv, LDAPMod ***list_of_attrs)
{
	char **attrs = NULL;
	int count, j;

	char *key;
	I32 klen;
	SV *val;

	count = hv_iterinit(attrs_hv);
	*list_of_attrs = (LDAPMod **)malloc((count+1)*sizeof(LDAPMod *));
	for (j = 0; j< count; j++) {
		LDAPMod mods;
		//val = hv_iternextsv(attrs_hv, (char **) &key, &klen);
		val = hv_iternextsv(attrs_hv, (char **) &mods.mod_type, &klen);
		if (SvTYPE(SvRV(val)) == SVt_PVAV) {
		    /* In case of multi-value */
			AV *val_array = (AV*)SvRV(val);
			int len;
			SV** elem;
			int i;

			len = av_len(val_array) + 1;
			mods.mod_values = (char **)malloc((len+1)*sizeof(char *));
			for (i = 0; i < len; i++) {
				elem = av_fetch(val_array, i, 0);
				if (elem != NULL) {
					mods.mod_values[i] = (char *)SvPV_nolen(*elem);
				}
			}
			mods.mod_values[i] = NULL;
		}else{
			mods.mod_values = (char **)malloc(2*sizeof(char *));
			mods.mod_values[0] = (char *)SvPV_nolen(val);
			mods.mod_values[1] = NULL;
		}
		(*list_of_attrs)[j] = (LDAPMod *)malloc(sizeof(LDAPMod));
		*((*list_of_attrs)[j]) = mods;
	}
	(*list_of_attrs)[j] = NULL;
}

AV*
get_entries(LDAP *ld, LDAPMessage *res)
{
	AV* entries = newAV();

	int i, j, k;
	char *dn, *a;
	LDAPMessage *e;
	BerElement *ptr;
	struct berval **vals;
	struct berval val;

	for(e = ldap_first_entry(ld, res), i = 0; e != NULL; e = ldap_next_entry(ld, e)) { 
		dn = ldap_get_dn(ld, e);
		/* one entry per hash */
		HV* entry_hash = newHV();
		/* attributes array */
		AV* attr_array = newAV();
		for ( a = ldap_first_attribute(ld, e, &ptr), j = 0; a != NULL; a = ldap_next_attribute(ld, e, ptr) ) {
			vals = ldap_get_values_len(ld, e, a);
			/* one attribute of an entry */
			HV* attr_hash = newHV();
			/* values of an attribute */
			AV* val_array = newAV();
			for (k = 0; vals[k] != NULL; k++) {
				val = *vals[k];
				av_store(val_array, k, newSVpv(val.bv_val, 0));
			}
			ldap_value_free_len(vals);

			hv_store(attr_hash, "type", 4, newSVpv(a, 0), 0);
			hv_store(attr_hash, "vals", 4, newRV_noinc((SV*)val_array), 0);
			av_store(attr_array, j++, newRV_noinc((SV*)attr_hash));
			ldap_memfree(a);
		}
		hv_store(entry_hash, "objectName", 10, newSVpv(dn, 0), 0);
		hv_store(entry_hash, "attributes", 10, newRV_noinc((SV*)attr_array), 0);
		/* setup a new object called Net::LDAPxs::Entry for every entry */
		HV* stash = gv_stashpv("Net::LDAPxs::Entry", GV_ADDWARN);
		SV* object;
		object = newRV_noinc((SV*)entry_hash);
		sv_bless(object, stash);

		av_store(entries, i++, object);

		ldap_memfree(dn);
		if (ptr != NULL)
			ldap_memfree(ptr);
	}
	return entries;
}


MODULE = Net::LDAPxs		PACKAGE = Net::LDAPxs		

REQUIRE:    1.929

INCLUDE: const-xs.inc


void *
_new(class, args_ref)
		char *class
		SV *args_ref
	PREINIT:
		HV *args;
		char *host;
		int port;
		int version;
		char *scheme;
		LDAP* ld;
		SV** svp;
	PPCODE:
		if (SvROK(args_ref) &&
			SvTYPE(SvRV(args_ref)) == SVt_PVHV)
		{
			args = (HV*)SvRV(args_ref);
		}else{
			Perl_croak(aTHX_ "Usage: Net::LDAPxs->new(HOST, port => PORT)");
		}

		if ((svp = hv_fetch(args, "host", 4, FALSE)))
			host = (char *)SvPV_nolen(*svp);
		if ((svp = hv_fetch(args, "port", 4, FALSE)))
			port = SvIV(*svp);
		if ((svp = hv_fetch(args, "version", 7, FALSE)))
			version = SvIV(*svp);
		if ((svp = hv_fetch(args, "scheme", 6, FALSE)))
			scheme = (char *)SvPV_nolen(*svp);

		ld = _connect(host, port, version, scheme);

		HV* stash = gv_stashpv("Net::LDAPxs", GV_ADDWARN);
		SV* object;
		HV* options = newHV();

		hv_store(options, "host", 4, newSVpv(host, 0), 0);
		hv_store(options, "port", 4, newSViv(port), 0);
		hv_store(options, "ld", 2, newSViv(ld), 0);
		object = newRV_noinc((SV*)options);
		sv_bless(object, stash);

		EXTEND(SP, 1);
		PUSHs(sv_2mortal(object));

int
_bind(class)
		HV* class
	PREINIT:
		LDAP* ld;
		int rc;
		SV** svp;
		char *binddn, *bindpasswd;
		int msgidp;
		struct berval   passwd = { 0, NULL };
	PPCODE:
		if ((svp = hv_fetch(class, "ld", 2, FALSE)))
			ld = (LDAP *)SvIV(*svp);
		if ((svp = hv_fetch(class, "binddn", 6, FALSE)))
			binddn = (char *)SvPV_nolen(*svp);
		if ((svp = hv_fetch(class, "bindpasswd", 10, FALSE)))
			bindpasswd = (char *)SvPV_nolen(*svp);

		passwd.bv_val = ber_strdup( bindpasswd );
		passwd.bv_len = strlen( passwd.bv_val );

		rc = ldap_sasl_bind( ld, binddn, LDAP_SASL_SIMPLE, &passwd, NULL, NULL, &msgidp );
		EXTEND(SP, 1);
		if (rc == LDAP_SUCCESS) {
			PUSHs(sv_2mortal(newSViv(rc)));
		}else{
			SV* errorno = newSVpv(ldap_err2string(rc), 0);
			PUSHs(sv_2mortal(newRV_noinc((SV*)errorno)));
			//fprintf( stderr, _("%s: ldap_sasl_bind: %s (%d)\n"),
			//	"bindpy", ldap_err2string( rc ), rc );
		}

void
_unbind(class)
		HV* class
	PREINIT:
		LDAP* ld;
		SV** svp;
	PPCODE:
		if ((svp = hv_fetch(class, "ld", 2, FALSE)))
			ld = (LDAP *)SvIV(*svp);
		ldap_unbind_ext(ld, NULL, NULL);

SV *
_search(class)
		HV* class
	PREINIT:
		LDAP* ld;
		int rc;
		SV** svp;

		char *base;
		int scope;
		char *filter;
		int sizelimit;

		SV** elem;
		AV* avref;
		int len, i;
		char **attrs = NULL;
		LDAPMessage *res;
		AV* entries;
	PPCODE:
		if ((svp = hv_fetch(class, "ld", 2, FALSE)))
			ld = (LDAP *)SvIV(*svp);
		if ((svp = hv_fetch(class, "base", 4, FALSE)))
			base = (char *)SvPV_nolen(*svp);
		if ((svp = hv_fetch(class, "scope", 5, FALSE)))
			scope = SvIV(*svp);
		if ((svp = hv_fetch(class, "filter", 6, FALSE)))
			filter = (char *)SvPV_nolen(*svp);
		if ((svp = hv_fetch(class, "sizelimit", 9, FALSE)))
			sizelimit = SvIV(*svp);
		if ((svp = hv_fetch(class, "attrs", 5, FALSE))) {
			avref = (AV*)SvRV(*svp);

			len = av_len(avref) + 1;
			attrs = (char **)malloc((len+1)*sizeof(char *));
			for (i = 0; i < len; i++) {
				elem = av_fetch(avref, i, 0);
				if (elem != NULL) {
					attrs[i] = (char *)SvPV_nolen(*elem);
				}
			}
			attrs[i] = NULL;
		}
		if (ldap_search_ext_s(ld, base, scope, filter, attrs, 0,
					NULL, NULL, LDAP_NO_LIMIT, sizelimit, &res) != LDAP_SUCCESS) {
			ldap_perror(ld, "ldap_search_ext_s");
			exit( EXIT_FAILURE );
		}
		free(attrs);

		/* store all entries */
		entries = get_entries(ld, res);
		ldap_msgfree(res);

		HV* search_result = newHV();
		hv_store(search_result, "parent", 6, newRV_noinc((SV*)class), 0);
		hv_store(search_result, "entries", 7, newRV_noinc((SV*)entries), 0);
		hv_store(search_result, "mesgid", 6, newSViv(i), 0);

		HV* stash;
		SV* blessed_result;
		stash = gv_stashpv("Net::LDAPxs::Search", GV_ADD);
		blessed_result = newRV_inc((SV*)search_result);
		sv_bless(blessed_result, stash);

		EXTEND(SP, 1);
		PUSHs(sv_2mortal(blessed_result));


int
count(ld, res)
	INPUT:
		LDAP *ld
		LDAPMessage *res
	CODE:
		RETVAL = ldap_count_entries(ld, res);
	OUTPUT:
		RETVAL

void
_add(class, dn, attrs_ref)
		HV* class
		char *dn
		SV* attrs_ref
	PREINIT:
		LDAP* ld;
		SV** svp;
		HV *attrs_hv;

		int msgidp=0;
	PPCODE:
		if ((svp = hv_fetch(class, "ld", 2, FALSE)))
			ld = (LDAP *)SvIV(*svp);

		if (SvROK(attrs_ref) &&
			SvTYPE(SvRV(attrs_ref)) == SVt_PVHV)
		{
			attrs_hv = (HV*)SvRV(attrs_ref);

			LDAPMod **list_of_attrs; 
			ldap_add_mods(attrs_hv, &list_of_attrs);
			if (ldap_add_ext(ld, dn, list_of_attrs, NULL, NULL, &msgidp) != LDAP_SUCCESS) {
				ldap_perror(ld, "ldap_add_ext");
				exit( EXIT_FAILURE );
			}
			free_attrs(list_of_attrs);
		}else{
			Perl_croak(aTHX_ "The value for option 'attrs' should be a hash ref");
		}

int
_compare(class, dn, attr, value)
		HV* class
		char *dn
		char *attr
		char *value
	PREINIT:
		LDAP* ld;
		SV** svp;

		struct berval bvalue = { 0, NULL };
		int rc;
	PPCODE:
		if ((svp = hv_fetch(class, "ld", 2, FALSE)))
			ld = (LDAP *)SvIV(*svp);

		bvalue.bv_val = strdup( value );
		bvalue.bv_len = strlen( bvalue.bv_val );

		rc = ldap_compare_ext_s(ld, dn, attr, &bvalue, NULL, NULL); 
		EXTEND(SP, 1);
		if (rc == LDAP_COMPARE_TRUE) {
			PUSHs(sv_2mortal(newSViv(rc)));
		}else{
			SV* errorno = newSVpv(ldap_err2string(rc), 0);
			PUSHs(sv_2mortal(newRV_noinc((SV*)errorno)));
		}

