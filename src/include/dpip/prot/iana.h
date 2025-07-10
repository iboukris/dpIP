/**
 * @file
 * IANA assigned numbers (RFC 1700 and successors)
 *
 * @defgroup iana IANA assigned numbers
 * @ingroup infrastructure
 */

/*
 * Copyright (c) 2017 Dirk Ziegelmeier.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the dpIP TCP/IP stack.
 *
 * Author: Dirk Ziegelmeier <dziegel@gmx.de>
 *
 */

#ifndef DPIP_HDR_PROT_IANA_H
#define DPIP_HDR_PROT_IANA_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup iana
 * Hardware types
 */
enum dpip_iana_hwtype {
  /** Ethernet */
	DPIP_IANA_HWTYPE_ETHERNET = 1
};

/**
 * @ingroup iana
 * Port numbers
 * https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.txt
 */
enum dpip_iana_port_number {
  /** SMTP */
	DPIP_IANA_PORT_SMTP = 25,
  /** DHCP server */
	DPIP_IANA_PORT_DHCP_SERVER = 67,
  /** DHCP client */
	DPIP_IANA_PORT_DHCP_CLIENT = 68,
  /** TFTP */
	DPIP_IANA_PORT_TFTP = 69,
  /** HTTP */
	DPIP_IANA_PORT_HTTP = 80,
  /** SNTP */
	DPIP_IANA_PORT_SNTP = 123,
  /** NETBIOS */
	DPIP_IANA_PORT_NETBIOS = 137,
  /** SNMP */
	DPIP_IANA_PORT_SNMP = 161,
  /** SNMP traps */
	DPIP_IANA_PORT_SNMP_TRAP = 162,
  /** HTTPS */
	DPIP_IANA_PORT_HTTPS = 443,
  /** SMTPS */
	DPIP_IANA_PORT_SMTPS = 465,
  /** MQTT */
	DPIP_IANA_PORT_MQTT = 1883,
  /** MDNS */
	DPIP_IANA_PORT_MDNS = 5353,
  /** Secure MQTT */
	DPIP_IANA_PORT_SECURE_MQTT = 8883
};

#ifdef __cplusplus
}
#endif
#endif				/* DPIP_HDR_PROT_IANA_H */
