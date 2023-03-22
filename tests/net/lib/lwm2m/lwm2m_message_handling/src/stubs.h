/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef STUBS_H
#define STUBS_H

#include <stdbool.h>
#include <stdint.h>

#include <zephyr/fff.h>
#include <zephyr/net/lwm2m.h>
#include <zephyr/ztest.h>

#include "lwm2m_object.h"
#include "lwm2m_rw_plain_text.h"

DECLARE_FAKE_VOID_FUNC(coap_pendings_clear, struct coap_pending *, size_t);
DECLARE_FAKE_VOID_FUNC(coap_replies_clear, struct coap_reply *, size_t);
DECLARE_FAKE_VOID_FUNC(remove_observer_from_list, struct lwm2m_ctx *, sys_snode_t *,
		       struct observe_node *);
DECLARE_FAKE_VOID_FUNC(coap_pending_clear, struct coap_pending *);
DECLARE_FAKE_VOID_FUNC(coap_reply_clear, struct coap_reply *);
DECLARE_FAKE_VALUE_FUNC(uint8_t *, coap_next_token);
DECLARE_FAKE_VALUE_FUNC(int, coap_packet_init, struct coap_packet *, uint8_t *, uint16_t, uint8_t,
			uint8_t, uint8_t, const uint8_t *, uint8_t, uint16_t);
DECLARE_FAKE_VALUE_FUNC(struct coap_pending *, coap_pending_next_unused, struct coap_pending *,
			size_t);
DECLARE_FAKE_VALUE_FUNC(int, coap_pending_init, struct coap_pending *, const struct coap_packet *,
			const struct sockaddr *, uint8_t);
DECLARE_FAKE_VOID_FUNC(coap_reply_init, struct coap_reply *, const struct coap_packet *);
DECLARE_FAKE_VALUE_FUNC(struct coap_reply *, coap_reply_next_unused, struct coap_reply *, size_t);
DECLARE_FAKE_VALUE_FUNC(int, lwm2m_rd_client_connection_resume, struct lwm2m_ctx *);
DECLARE_FAKE_VOID_FUNC(engine_update_tx_time);
DECLARE_FAKE_VOID_FUNC(http_parser_url_init, struct http_parser_url *);
DECLARE_FAKE_VALUE_FUNC(int, http_parser_parse_url, const char *, size_t, int,
			struct http_parser_url *);
DECLARE_FAKE_VALUE_FUNC(int, coap_block_transfer_init, struct coap_block_context *,
			enum coap_block_size, size_t);
DECLARE_FAKE_VALUE_FUNC(uint16_t, lwm2m_atou16, const uint8_t *, uint16_t, uint16_t *);
DECLARE_FAKE_VALUE_FUNC(int, lwm2m_delete_obj_inst, uint16_t, uint16_t);
DECLARE_FAKE_VOID_FUNC(engine_trigger_update, bool);
DECLARE_FAKE_VALUE_FUNC(int, do_read_op_plain_text, struct lwm2m_message *, int);
DECLARE_FAKE_VALUE_FUNC(int, do_read_op_cbor, struct lwm2m_message *);
DECLARE_FAKE_VALUE_FUNC(int, do_read_op_senml_cbor, struct lwm2m_message *);
DECLARE_FAKE_VALUE_FUNC(int, do_read_op_senml_json, struct lwm2m_message *);
DECLARE_FAKE_VALUE_FUNC(int, do_composite_read_op_senml_cbor, struct lwm2m_message *);
DECLARE_FAKE_VALUE_FUNC(int, do_composite_read_op_senml_json, struct lwm2m_message *);
DECLARE_FAKE_VALUE_FUNC(int, do_discover_op_link_format, struct lwm2m_message *, bool);
DECLARE_FAKE_VALUE_FUNC(int, do_write_op_plain_text, struct lwm2m_message *);
DECLARE_FAKE_VALUE_FUNC(int, do_write_op_cbor, struct lwm2m_message *);
DECLARE_FAKE_VALUE_FUNC(int, do_write_op_senml_cbor, struct lwm2m_message *);
DECLARE_FAKE_VALUE_FUNC(int, do_write_op_senml_json, struct lwm2m_message *);
DECLARE_FAKE_VALUE_FUNC(int, path_to_objs, const struct lwm2m_obj_path *,
			struct lwm2m_engine_obj_inst **, struct lwm2m_engine_obj_field **,
			struct lwm2m_engine_res **, struct lwm2m_engine_res_inst **);
DECLARE_FAKE_VALUE_FUNC(const uint8_t *, coap_packet_get_payload, const struct coap_packet *, uint16_t *);
DECLARE_FAKE_VALUE_FUNC(uint8_t, coap_header_get_code, const struct coap_packet *);
DECLARE_FAKE_VALUE_FUNC(uint8_t, coap_header_get_token, const struct coap_packet *, uint8_t *);
DECLARE_FAKE_VALUE_FUNC(int, coap_find_options, const struct coap_packet *, uint16_t, struct coap_option *, uint16_t);
DECLARE_FAKE_VALUE_FUNC(unsigned int, coap_option_value_to_int, const struct coap_option *);
DECLARE_FAKE_VALUE_FUNC(struct lwm2m_engine_obj *, get_engine_obj, int);
DECLARE_FAKE_VALUE_FUNC(int, coap_get_option_int, const struct coap_packet *, uint16_t);
DECLARE_FAKE_VALUE_FUNC(int, coap_update_from_block, const struct coap_packet *, struct coap_block_context *);
DECLARE_FAKE_VALUE_FUNC(int, lwm2m_engine_observation_handler, struct lwm2m_message *, int, uint16_t, bool);
DECLARE_FAKE_VALUE_FUNC(int, lwm2m_write_attr_handler, struct lwm2m_engine_obj *, struct lwm2m_message *);
DECLARE_FAKE_VALUE_FUNC(int, coap_append_block1_option, struct coap_packet *, struct coap_block_context *);
DECLARE_FAKE_VOID_FUNC(engine_bootstrap_finish);
DECLARE_FAKE_VALUE_FUNC(int, bootstrap_delete, struct lwm2m_message *);
DECLARE_FAKE_VALUE_FUNC(int, udp_handle_request, struct coap_packet *, struct lwm2m_message *);
DECLARE_FAKE_VALUE_FUNC(struct lwm2m_message *, lwm2m_get_ongoing_rd_msg);
DECLARE_FAKE_VALUE_FUNC(uint16_t, coap_next_id);
DECLARE_FAKE_VALUE_FUNC(int, coap_packet_parse, struct coap_packet *, uint8_t *, uint16_t, struct coap_option *, uint8_t);
DECLARE_FAKE_VALUE_FUNC(struct coap_pending *, coap_pending_received, const struct coap_packet *, struct coap_pending *, size_t);
DECLARE_FAKE_VALUE_FUNC(uint8_t, coap_header_get_type, const struct coap_packet *);
DECLARE_FAKE_VALUE_FUNC(char *, lwm2m_sprint_ip_addr, const struct sockaddr *);
DECLARE_FAKE_VALUE_FUNC(uint16_t, coap_header_get_id, const struct coap_packet *);
DECLARE_FAKE_VALUE_FUNC(struct coap_reply *, coap_response_received, const struct coap_packet *, const struct sockaddr *, struct coap_reply *, size_t);
DECLARE_FAKE_VOID_FUNC(lwm2m_registry_lock);
DECLARE_FAKE_VOID_FUNC(lwm2m_registry_unlock);
DECLARE_FAKE_VALUE_FUNC(sys_slist_t *, lwm2m_engine_obj_list);
DECLARE_FAKE_VALUE_FUNC(sys_slist_t *, lwm2m_engine_obj_inst_list);
DECLARE_FAKE_VALUE_FUNC(int, coap_append_option_int, struct coap_packet *, uint16_t, unsigned int);
DECLARE_FAKE_VALUE_FUNC(int, coap_packet_append_payload_marker, struct coap_packet *);
DECLARE_FAKE_VALUE_FUNC(bool, lwm2m_engine_shall_report_obj_version, const struct lwm2m_engine_obj *);
DECLARE_FAKE_VALUE_FUNC(struct observe_node *, engine_observe_node_discover, sys_slist_t *, sys_snode_t **, sys_slist_t *, const uint8_t *, uint8_t);
DECLARE_FAKE_VALUE_FUNC(int, lwm2m_rd_client_timeout, struct lwm2m_ctx *);
DECLARE_FAKE_VALUE_FUNC(char *, sprint_token, const uint8_t *, uint8_t);
DECLARE_FAKE_VALUE_FUNC(int, engine_remove_observer_by_token, struct lwm2m_ctx *, const uint8_t *, uint8_t);
DECLARE_FAKE_VALUE_FUNC(int, do_send_op_senml_cbor, struct lwm2m_message *, sys_slist_t *);
DECLARE_FAKE_VALUE_FUNC(int, do_send_op_senml_json, struct lwm2m_message *, sys_slist_t *);
DECLARE_FAKE_VALUE_FUNC(struct lwm2m_engine_obj_inst *, get_engine_obj_inst, int, int);
DECLARE_FAKE_VALUE_FUNC(bool, lwm2m_rd_client_is_registred, struct lwm2m_ctx *);
DECLARE_FAKE_VALUE_FUNC(bool, lwm2m_server_get_mute_send, uint16_t);
DECLARE_FAKE_VOID_FUNC(lwm2m_engine_path_list_init, sys_slist_t *, sys_slist_t *, struct lwm2m_obj_path_list *, uint8_t);
DECLARE_FAKE_VALUE_FUNC(int, lwm2m_engine_add_path_to_list, sys_slist_t *, sys_slist_t *, const struct lwm2m_obj_path *);
DECLARE_FAKE_VOID_FUNC(lwm2m_engine_clear_duplicate_path, sys_slist_t *, sys_slist_t *);
DECLARE_FAKE_VALUE_FUNC(int, coap_packet_append_option, struct coap_packet *, uint16_t, const uint8_t *, uint16_t);
DECLARE_FAKE_VALUE_FUNC(struct lwm2m_time_series_resource *, lwm2m_cache_entry_get_by_object, struct lwm2m_obj_path *);
DECLARE_FAKE_VALUE_FUNC(struct lwm2m_engine_obj_field *, lwm2m_get_engine_obj_field, struct lwm2m_engine_obj *, int);
DECLARE_FAKE_VALUE_FUNC(struct lwm2m_engine_obj_inst *, next_engine_obj_inst, int, int);
DECLARE_FAKE_VALUE_FUNC(int, lwm2m_notify_observer_path, const struct lwm2m_obj_path *);
DECLARE_FAKE_VALUE_FUNC(int, do_composite_read_op_for_parsed_list_senml_json, struct lwm2m_message *, sys_slist_t *);
DECLARE_FAKE_VALUE_FUNC(int, do_composite_read_op_for_parsed_path_senml_cbor, struct lwm2m_message *, sys_slist_t *);

#define DO_FOREACH_FAKE(FUNC)                                                                      \
	do {                                                                                       \
		FUNC(coap_pendings_clear)                                                          \
		FUNC(coap_replies_clear)                                                           \
		FUNC(remove_observer_from_list)                                                    \
		FUNC(coap_pending_clear)                                                           \
		FUNC(coap_reply_clear)                                                             \
		FUNC(coap_next_token)                                                              \
		FUNC(coap_packet_init)                                                             \
		FUNC(coap_pending_next_unused)                                                     \
		FUNC(coap_pending_init)                                                            \
		FUNC(coap_reply_init)                                                              \
		FUNC(coap_reply_next_unused)                                                       \
		FUNC(lwm2m_rd_client_connection_resume)                                            \
		FUNC(engine_update_tx_time)                                                        \
		FUNC(http_parser_url_init)                                                         \
		FUNC(http_parser_parse_url)                                                        \
		FUNC(coap_block_transfer_init)                                                     \
		FUNC(lwm2m_atou16)                                                                 \
		FUNC(lwm2m_delete_obj_inst)                                                        \
		FUNC(engine_trigger_update)                                                        \
		FUNC(do_read_op_plain_text)                                                        \
		FUNC(do_read_op_cbor)                                                              \
		FUNC(do_read_op_senml_cbor)                                                        \
		FUNC(do_read_op_senml_json)                                                        \
		FUNC(do_composite_read_op_senml_cbor)                                                        \
		FUNC(do_composite_read_op_senml_json)                                                        \
		FUNC(do_discover_op_link_format)                                                       	 \
		FUNC(do_write_op_plain_text)                                                        \
		FUNC(do_write_op_cbor)                                                        \
		FUNC(do_write_op_senml_cbor)                                                        \
		FUNC(do_write_op_senml_json)                                                        \
		FUNC(path_to_objs)                                                        \
		FUNC(coap_packet_get_payload)                                                        \
		FUNC(coap_header_get_code)                                                        \
		FUNC(coap_header_get_token)                                                        \
		FUNC(coap_find_options)                                                        \
		FUNC(coap_option_value_to_int)                                                        \
		FUNC(get_engine_obj)                                                        \
		FUNC(coap_get_option_int)                                                        \
		FUNC(coap_update_from_block)                                                        \
		FUNC(lwm2m_engine_observation_handler)                                                        \
		FUNC(lwm2m_write_attr_handler)                                                        \
		FUNC(coap_append_block1_option)                                                        \
		FUNC(engine_bootstrap_finish)                                                        \
		FUNC(bootstrap_delete)                                                        \
		FUNC(udp_handle_request)                                                        \
		FUNC(lwm2m_get_ongoing_rd_msg)                                                        \
		FUNC(coap_next_id)                                                        \
		FUNC(coap_packet_parse)                                                        \
		FUNC(coap_pending_received)                                                        \
		FUNC(coap_header_get_type)                                                        \
		FUNC(lwm2m_sprint_ip_addr)                                                        \
		FUNC(coap_header_get_id)                                                        \
		FUNC(coap_response_received)                                                        \
		FUNC(lwm2m_registry_lock)                                                        \
		FUNC(lwm2m_registry_unlock)                                                        \
		FUNC(lwm2m_engine_obj_list)                                                        \
		FUNC(lwm2m_engine_obj_inst_list)                                                        \
		FUNC(coap_append_option_int)                                                        \
		FUNC(coap_packet_append_payload_marker)                                                        \
		FUNC(lwm2m_engine_shall_report_obj_version)                                                        \
		FUNC(engine_observe_node_discover)                                                        \
		FUNC(lwm2m_rd_client_timeout)                                                        \
		FUNC(sprint_token)                                                        \
		FUNC(engine_remove_observer_by_token)                                                        \
		FUNC(do_send_op_senml_cbor)                                                        \
		FUNC(do_send_op_senml_json)                                                        \
		FUNC(get_engine_obj_inst)                                                        \
		FUNC(lwm2m_rd_client_is_registred)                                                        \
		FUNC(lwm2m_server_get_mute_send)                                                        \
		FUNC(lwm2m_engine_path_list_init)                                                        \
		FUNC(lwm2m_engine_add_path_to_list)                                                        \
		FUNC(lwm2m_engine_clear_duplicate_path)                                                        \
		FUNC(coap_packet_append_option)                                                        \
		FUNC(lwm2m_cache_entry_get_by_object)                                                        \
		FUNC(lwm2m_get_engine_obj_field)                                                        \
		FUNC(next_engine_obj_inst)                                                        \
		FUNC(lwm2m_notify_observer_path)                                                        \
		FUNC(do_composite_read_op_for_parsed_list_senml_json)                                                        \
		FUNC(do_composite_read_op_for_parsed_path_senml_cbor)                                                        \
	} while (0)

#endif /* STUBS_H */
