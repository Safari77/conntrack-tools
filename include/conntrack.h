#ifndef _CONNTRACK_H
#define _CONNTRACK_H

#include "linux_list.h"
#include <stdint.h>

#define PROGNAME "conntrack"

#include <netinet/in.h>

#include <linux/netfilter/nf_conntrack_common.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#define NUMBER_OF_CMD   19
#define NUMBER_OF_OPT   29

struct nf_conntrack;

struct ctproto_handler {
	struct list_head 	head;

	const char		*name;
	uint16_t 		protonum;
	const char		*version;

	uint32_t		protoinfo_attr;

	int (*parse_opts)(char c,
			  struct nf_conntrack *ct,
			  struct nf_conntrack *exptuple,
			  struct nf_conntrack *mask,
			  unsigned int *flags);

	void (*final_check)(unsigned int flags,
			    unsigned int command,
			    struct nf_conntrack *ct);

	const struct ct_print_opts *print_opts;

	void (*help)(void);

	struct option 		*opts;

	unsigned int		option_offset;
};

enum exittype {
	OTHER_PROBLEM = 1,
	PARAMETER_PROBLEM,
	VERSION_PROBLEM
};

int generic_opt_check(int options, int nops,
		      char *optset, const char *optflg[],
		      unsigned int *coupled_flags, int coupled_flags_size,
		      int *partial);
void exit_error(enum exittype status, const char *msg, ...);

extern void register_proto(struct ctproto_handler *h);

enum ct_attr_type {
	CT_ATTR_TYPE_NONE = 0,
	CT_ATTR_TYPE_U8,
	CT_ATTR_TYPE_BE16,
	CT_ATTR_TYPE_U16,
	CT_ATTR_TYPE_BE32,
	CT_ATTR_TYPE_U32,
	CT_ATTR_TYPE_U64,
	CT_ATTR_TYPE_U32_BITMAP,
	CT_ATTR_TYPE_IPV4,
	CT_ATTR_TYPE_IPV6,
};

struct ct_print_opts {
	const char		*name;
	enum nf_conntrack_attr	type;
	enum ct_attr_type	datatype;
	short			val_mapping_count;
	const char		**val_mapping;
};

extern int ct_snprintf_opts(char *buf, unsigned int len,
			    const struct nf_conntrack *ct,
			    const struct ct_print_opts *attrs);

extern void register_tcp(void);
extern void register_udp(void);
extern void register_udplite(void);
extern void register_sctp(void);
extern void register_dccp(void);
extern void register_icmp(void);
extern void register_icmpv6(void);
extern void register_gre(void);
extern void register_unknown(void);

#endif
