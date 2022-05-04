/* Copyright (C) 2017 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/*
 * DO NOT EDIT. This file is automatically generated.
 */

#ifndef __RUST_DNS_DNS_GEN_H__
#define __RUST_DNS_DNS_GEN_H__

void * rs_dns_state_new(void);
void * rs_dns_state_tcp_new(void);
void rs_dns_state_free(void * state);
void rs_dns_state_tx_free(RSDNSState * state, uint64_t tx_id);
int8_t rs_dns_parse_request(Flow * _flow, RSDNSState * state, void * _pstate, const uint8_t * input, uint32_t input_len, void * _data);
int8_t rs_dns_parse_response(Flow * _flow, RSDNSState * state, void * _pstate, const uint8_t * input, uint32_t input_len, void * _data);
int8_t rs_dns_parse_request_tcp(Flow * _flow, RSDNSState * state, void * _pstate, const uint8_t * input, uint32_t input_len, void * _data);
int8_t rs_dns_parse_response_tcp(Flow * _flow, RSDNSState * state, void * _pstate, const uint8_t * input, uint32_t input_len, void * _data);
int rs_dns_state_progress_completion_status(uint8_t _direction);
uint8_t rs_dns_tx_get_alstate_progress(RSDNSTransaction * _tx, uint8_t _direction);
void rs_dns_tx_set_detect_flags(RSDNSTransaction * tx, uint8_t dir, uint64_t flags);
uint64_t rs_dns_tx_get_detect_flags(RSDNSTransaction * tx, uint8_t dir);
void rs_dns_tx_set_logged(RSDNSState * _state, RSDNSTransaction * tx, uint32_t logged);
uint32_t rs_dns_tx_get_logged(RSDNSState * _state, RSDNSTransaction * tx);
uint64_t rs_dns_state_get_tx_count(RSDNSState * state);
RSDNSTransaction * rs_dns_state_get_tx(RSDNSState * state, uint64_t tx_id);
void rs_dns_state_set_tx_detect_state(RSDNSTransaction * tx, DetectEngineState * de_state);
DetectEngineState * rs_dns_state_get_tx_detect_state(RSDNSTransaction * tx);
AppLayerDecoderEvents * rs_dns_state_get_events(void * tx);
uint8_t rs_dns_tx_get_query_name(RSDNSTransaction * tx, uint16_t i, const uint8_t ** buf, uint32_t * len);
uint16_t rs_dns_tx_get_tx_id(RSDNSTransaction * tx);
uint16_t rs_dns_tx_get_response_flags(RSDNSTransaction * tx);
uint8_t rs_dns_tx_get_query_rrtype(RSDNSTransaction * tx, uint16_t i, uint16_t * rrtype);
uint8_t rs_dns_probe(const uint8_t * input, uint32_t len, uint8_t * rdir);
uint8_t rs_dns_probe_tcp(uint8_t direction, const uint8_t * input, uint32_t len, uint8_t * rdir);

#endif /* ! __RUST_DNS_DNS_GEN_H__ */