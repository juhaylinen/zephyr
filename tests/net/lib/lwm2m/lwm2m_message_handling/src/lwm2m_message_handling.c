/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/ztest.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/http/parser_url.h>

#include "lwm2m_engine.h"
#include "lwm2m_object.h"
#include "lwm2m_util.h"

#include "stubs.h"

LOG_MODULE_REGISTER(lwm2m_message_handling_test);

DEFINE_FFF_GLOBALS;
#define FFF_FAKES_LIST(FAKE)

#define MY_OBJ_ID 10
#define MY_OBJ_INST_ID 1

static sys_slist_t my_obj_list;
static sys_slist_t my_obj_inst_list;

int parse_url(const char *buf, size_t buflen, int is_connect, struct http_parser_url *u)
{
	u->field_data[0].off = 0;
	u->field_data[0].len = 5;

	return 0;
}

sys_slist_t *lwm2m_engine_obj_list_custom_fake(void)
{
	LOG_INF("my obj list");
	return &my_obj_list;
}

sys_slist_t *lwm2m_engine_obj_inst_list_custom_fake(void)
{
	LOG_INF("my obj inst list");
	return &my_obj_inst_list;
}

int coap_find_options_custom_fake(const struct coap_packet *cpkt, uint16_t code, struct coap_option *options, uint16_t veclen)
{
	options[0].len = 1;
	options[0].value[0] = 1;

	return 1;
}

uint16_t lwm2m_atou16_custom_fake(const uint8_t *buf, uint16_t buflen, uint16_t *len)
{
	*len = 1;
	return 10;
}
//static int udp_handle_request(struct coap_packet *request, struct lwm2m_message *msg)
//{
//	return 0;
//}

static void setup(void *data)
{
	/* Register resets */
	DO_FOREACH_FAKE(RESET_FAKE);

	/* reset common FFF internal structures */
	FFF_RESET_HISTORY();

	sys_slist_init(&my_obj_list);
	sys_slist_init(&my_obj_inst_list);

	lwm2m_engine_obj_list_fake.custom_fake = lwm2m_engine_obj_list_custom_fake;
	lwm2m_engine_obj_inst_list_fake.custom_fake = lwm2m_engine_obj_inst_list_custom_fake;
	coap_find_options_fake.custom_fake = coap_find_options_custom_fake;
	lwm2m_atou16_fake.custom_fake = lwm2m_atou16_custom_fake;
}

static int put_corelink_fake(struct lwm2m_output_context *out, const struct lwm2m_obj_path *path)
{
	if (path->obj_id != MY_OBJ_ID){
		return -1;
	}

	return 0;
}

FAKE_VALUE_FUNC(int, put_begin, struct lwm2m_output_context *, struct lwm2m_obj_path *);
FAKE_VALUE_FUNC(int, put_end, struct lwm2m_output_context *, struct lwm2m_obj_path *);
FAKE_VALUE_FUNC(int, put_begin_oi, struct lwm2m_output_context *, struct lwm2m_obj_path *);
FAKE_VALUE_FUNC(int, put_end_oi, struct lwm2m_output_context *, struct lwm2m_obj_path *);
FAKE_VALUE_FUNC(int, put_begin_r, struct lwm2m_output_context *, struct lwm2m_obj_path *);
FAKE_VALUE_FUNC(int, put_end_r, struct lwm2m_output_context *, struct lwm2m_obj_path *);
FAKE_VALUE_FUNC(int, put_begin_ri, struct lwm2m_output_context *, struct lwm2m_obj_path *);
FAKE_VALUE_FUNC(int, put_end_ri, struct lwm2m_output_context *, struct lwm2m_obj_path *);
FAKE_VALUE_FUNC(int, put_s8, struct lwm2m_output_context *, struct lwm2m_obj_path *, int8_t);
FAKE_VALUE_FUNC(int, put_s16, struct lwm2m_output_context *, struct lwm2m_obj_path *, int16_t);
FAKE_VALUE_FUNC(int, put_s32, struct lwm2m_output_context *, struct lwm2m_obj_path *, int32_t);
FAKE_VALUE_FUNC(int, put_s64, struct lwm2m_output_context *, struct lwm2m_obj_path *, int64_t);
FAKE_VALUE_FUNC(int, put_time, struct lwm2m_output_context *, struct lwm2m_obj_path *, time_t);
FAKE_VALUE_FUNC(int, put_string, struct lwm2m_output_context *, struct lwm2m_obj_path *, char *,
		size_t);
FAKE_VALUE_FUNC(int, put_float, struct lwm2m_output_context *, struct lwm2m_obj_path *, double *);
FAKE_VALUE_FUNC(int, put_bool, struct lwm2m_output_context *, struct lwm2m_obj_path *, bool);
FAKE_VALUE_FUNC(int, put_opaque, struct lwm2m_output_context *, struct lwm2m_obj_path *, char *,
		size_t);
FAKE_VALUE_FUNC(int, put_objlnk, struct lwm2m_output_context *, struct lwm2m_obj_path *,
		struct lwm2m_objlnk *);

const struct lwm2m_writer my_writer = {
	.put_corelink = put_corelink_fake,
	.put_begin = put_begin,
	.put_end = put_end,
	.put_begin_oi = put_begin_oi,
	.put_end_oi = put_end_oi,
	.put_begin_r = put_begin_r,
	.put_end_r = put_end_r,
	.put_begin_ri = put_begin_oi,
	.put_end_ri = put_end_oi,
	.put_s8 = put_s8,
	.put_s16 = put_s16,
	.put_s32 = put_s32,
	.put_s64 = put_s64,
	.put_time = put_time,
	.put_string = put_string,
	.put_float = put_float,
	.put_bool = put_bool,
	.put_opaque = put_opaque,
	.put_objlnk = put_objlnk,
};

static int get_opaque_fake(struct lwm2m_input_context *in, uint8_t *buf,
			  size_t buflen, struct lwm2m_opaque_context *opaque,
			  bool *last_block)
{
	*last_block = true;
	return 1;
}

FAKE_VALUE_FUNC(int, get_string, struct lwm2m_input_context *, uint8_t *, size_t);
FAKE_VALUE_FUNC(int, get_time, struct lwm2m_input_context *, time_t *);
FAKE_VALUE_FUNC(int, get_s32, struct lwm2m_input_context *, int32_t *);
FAKE_VALUE_FUNC(int, get_s64, struct lwm2m_input_context *, int64_t *);
FAKE_VALUE_FUNC(int, get_bool, struct lwm2m_input_context *, bool *);
FAKE_VALUE_FUNC(int, get_float, struct lwm2m_input_context *, double *);
FAKE_VALUE_FUNC(int, get_objlnk, struct lwm2m_input_context *, struct lwm2m_objlnk *);

const struct lwm2m_reader my_reader = {
	.get_opaque = get_opaque_fake,
	.get_string = get_string,
	.get_time = get_time,
	.get_s64 = get_s64,
	.get_s32 = get_s32,
	.get_bool = get_bool,
	.get_float = get_float,
	.get_objlnk = get_objlnk,
};

ZTEST_SUITE(lwm2m_message_handling, NULL, NULL, setup, NULL, NULL);


#if 1
ZTEST(lwm2m_message_handling, test_handle_request_delete)
{
	int ret;
	struct lwm2m_ctx ctx;
	struct lwm2m_message msg;
	struct coap_packet req;
	struct coap_pending pending;
	struct lwm2m_engine_obj obj;

	(void)memset(&ctx, 0x0, sizeof(ctx));
	(void)memset(&msg, 0x0, sizeof(msg));

	ctx.bootstrap_mode = false;
	msg.ctx = &ctx;
	msg.path = LWM2M_OBJ(MY_OBJ_ID, MY_OBJ_INST_ID);
	coap_header_get_code_fake.return_val = COAP_METHOD_DELETE;
	coap_pending_next_unused_fake.return_val = &pending;
	coap_header_get_token_fake.return_val = 1;
	get_engine_obj_fake.return_val = &obj;
	coap_get_option_int_fake.return_val = 1;
	coap_option_value_to_int_fake.return_val = LWM2M_FORMAT_APP_CBOR;
	
	ret = handle_request(&req, &msg);
	zassert_equal(ret, 0);
	zassert_equal(lwm2m_delete_obj_inst_fake.call_count, 1, "Object instance not deleted.");
}

ZTEST(lwm2m_message_handling, test_handle_request_put)
{
	int ret;
	struct lwm2m_ctx ctx;
	struct lwm2m_message msg;
	struct coap_packet req;
	struct coap_pending pending;
	struct lwm2m_engine_obj obj;

	(void)memset(&ctx, 0x0, sizeof(ctx));
	(void)memset(&msg, 0x0, sizeof(msg));

	ctx.bootstrap_mode = true;
	msg.ctx = &ctx;
	msg.path = LWM2M_OBJ(MY_OBJ_ID, MY_OBJ_INST_ID);
	coap_header_get_code_fake.return_val = COAP_METHOD_PUT;
	coap_pending_next_unused_fake.return_val = &pending;
	coap_header_get_token_fake.return_val = 1;
	get_engine_obj_fake.return_val = &obj;
	coap_get_option_int_fake.return_val = 1;
	coap_option_value_to_int_fake.return_val = LWM2M_FORMAT_APP_SENML_CBOR;
	ret = handle_request(&req, &msg);
	zassert_equal(ret, 0);

	zassert_equal(do_write_op_senml_cbor_fake.call_count, 1, "Write operation for senml cbor not done.");
}

ZTEST(lwm2m_message_handling, test_handle_request_get)
{
	int ret;
	struct lwm2m_ctx ctx;
	struct lwm2m_message msg;
	struct coap_packet req;
	struct coap_pending pending;

	(void)memset(&ctx, 0x0, sizeof(ctx));
	(void)memset(&msg, 0x0, sizeof(msg));

	ctx.bootstrap_mode = true;
	msg.ctx = &ctx;
	msg.path = LWM2M_OBJ(MY_OBJ_ID, MY_OBJ_INST_ID);
	coap_header_get_code_fake.return_val = COAP_METHOD_GET;
	coap_pending_next_unused_fake.return_val = &pending;
	coap_header_get_token_fake.return_val = 1;
	coap_option_value_to_int_fake.return_val = LWM2M_FORMAT_APP_SENML_CBOR;
	ret = handle_request(&req, &msg);
	zassert_equal(ret, 0);
}

ZTEST(lwm2m_message_handling, test_generate_notify_message_composite)
{
	int ret;
	struct lwm2m_ctx ctx;
	struct observe_node obs;
	struct coap_pending pending;
	struct coap_reply reply;
	struct lwm2m_obj_path_list entry;
	struct lwm2m_engine_obj_inst obj_inst;

	sys_slist_init(&obs.path_list);
	entry.path = LWM2M_OBJ(MY_OBJ_ID, MY_OBJ_INST_ID);
	sys_slist_append(&obs.path_list, &entry.node);
	obs.composite = true;
	obs.format = LWM2M_FORMAT_APP_SEML_JSON;
	(void)memset(&ctx, 0x0, sizeof(ctx));
	lwm2m_engine_context_init(&ctx);

	coap_pending_next_unused_fake.return_val = &pending;
	coap_reply_next_unused_fake.return_val = &reply;
	get_engine_obj_inst_fake.return_val = &obj_inst;
	ret = generate_notify_message(&ctx, &obs, NULL);
	zassert_equal(ret, 0);
	lwm2m_engine_context_close(&ctx);
}

ZTEST(lwm2m_message_handling, test_generate_notify_message)
{
	int ret;
	struct lwm2m_ctx ctx;
	struct observe_node obs;
	struct coap_pending pending;
	struct coap_reply reply;
	struct lwm2m_obj_path path;
	struct lwm2m_obj_path_list entry;
	struct lwm2m_engine_obj_inst obj_inst;

	sys_slist_init(&obs.path_list);
	path = LWM2M_OBJ(MY_OBJ_ID, MY_OBJ_INST_ID);
	entry.path = path;
	sys_slist_append(&obs.path_list, &entry.node);
	//obs.composite = true;
	obs.format = LWM2M_FORMAT_APP_SENML_CBOR;
	(void)memset(&ctx, 0x0, sizeof(ctx));
	lwm2m_engine_context_init(&ctx);

	coap_pending_next_unused_fake.return_val = &pending;
	coap_reply_next_unused_fake.return_val = &reply;
	get_engine_obj_inst_fake.return_val = &obj_inst;
	ret = generate_notify_message(&ctx, &obs, NULL);
	zassert_equal(ret, 0);
	lwm2m_engine_context_close(&ctx);
}

ZTEST(lwm2m_message_handling, test_generate_notify_message_fail_reply)
{
	int ret;
	struct lwm2m_ctx ctx;
	struct observe_node obs;
	struct coap_pending pending;

	sys_slist_init(&obs.path_list);
	obs.composite = true;
	obs.format = LWM2M_FORMAT_APP_SENML_CBOR;
	(void)memset(&ctx, 0x0, sizeof(ctx));
	lwm2m_engine_context_init(&ctx);

	coap_pending_next_unused_fake.return_val = &pending;
	ret = generate_notify_message(&ctx, &obs, NULL);
	zassert_equal(ret, -ENOMEM);
	lwm2m_engine_context_close(&ctx);
}

ZTEST(lwm2m_message_handling, test_generate_notify_message_fail_pending)
{
	int ret;
	struct lwm2m_ctx ctx;
	struct observe_node obs;

	sys_slist_init(&obs.path_list);
	obs.composite = true;
	obs.format = LWM2M_FORMAT_APP_SENML_CBOR;
	(void)memset(&ctx, 0x0, sizeof(ctx));
	lwm2m_engine_context_init(&ctx);

	ret = generate_notify_message(&ctx, &obs, NULL);
	zassert_equal(ret, -ENOMEM);
	lwm2m_engine_context_close(&ctx);
}

ZTEST(lwm2m_message_handling, test_discover_handler)
{
	int ret;
	struct lwm2m_message msg;
	struct coap_packet out_pkt;
	struct lwm2m_engine_obj obj;
	struct lwm2m_engine_obj_inst obj_inst;
	struct lwm2m_engine_res resources;

 	(void)memset(&obj, 0x0, sizeof(obj));
	(void)memset(&obj_inst, 0x0, sizeof(obj_inst));

	obj.obj_id = MY_OBJ_ID;
	obj_inst.obj = &obj;
	obj_inst.obj_inst_id = MY_OBJ_INST_ID;
	obj_inst.resources = &resources;
	obj_inst.resource_count = 1;
	sys_slist_append(&my_obj_list, &obj.node);
	sys_slist_append(&my_obj_inst_list, &obj_inst.node);
	msg.path = LWM2M_OBJ(MY_OBJ_ID, MY_OBJ_INST_ID);
	msg.out.writer = &my_writer;
	msg.out.out_cpkt = &out_pkt;

	ret = lwm2m_discover_handler(&msg, false);
	zassert_equal(ret, 0);
}

ZTEST(lwm2m_message_handling, test_udp_receive)
{
	struct lwm2m_ctx ctx;
	struct sockaddr addr;
	uint8_t data = 0;

	(void)memset(&ctx, 0x0, sizeof(ctx));

	lwm2m_udp_receive(&ctx, &data, sizeof(data), &addr, udp_handle_request);

	zassert_equal(coap_header_get_code_fake.call_count, 1, "coap_header_get_code() not called");
	zassert_equal(coap_header_get_id_fake.call_count, 1, "coap_header_get_id() not called");
	zassert_equal(udp_handle_request_fake.call_count, 1, "Response to the request was not processed.");
}

ZTEST(lwm2m_message_handling, test_udp_receive_pending)
{
	struct lwm2m_ctx ctx;
	struct sockaddr addr;
	struct coap_pending pending;
	struct lwm2m_message msg;
	uint8_t data = 0;

	(void)memset(&ctx, 0x0, sizeof(ctx));

	coap_pending_received_fake.return_val = &pending;
	coap_header_get_type_fake.return_val = COAP_TYPE_ACK;
	msg.code = COAP_METHOD_GET;
	msg.pending = &pending;
	lwm2m_get_ongoing_rd_msg_fake.return_val = &msg;
	lwm2m_udp_receive(&ctx, &data, sizeof(data), &addr, udp_handle_request);

	zassert_equal(coap_header_get_code_fake.call_count, 1, "coap_header_get_code() not called");
}

ZTEST(lwm2m_message_handling, test_udp_receive_reply)
{
	struct lwm2m_ctx ctx;
	struct sockaddr addr;
	struct coap_reply reply;
	struct lwm2m_message msg;
	uint8_t data = 0;

	(void)memset(&ctx, 0x0, sizeof(ctx));

	coap_response_received_fake.return_val = &reply;
	coap_header_get_type_fake.return_val = COAP_TYPE_CON;
	msg.code = COAP_METHOD_GET;
	msg.reply = &reply;
	lwm2m_get_ongoing_rd_msg_fake.return_val = &msg;
	lwm2m_udp_receive(&ctx, &data, sizeof(data), &addr, udp_handle_request);

	zassert_equal(coap_header_get_id_fake.call_count, 1, "coap_header_get_id() not called");
}

ZTEST(lwm2m_message_handling, test_lwm2m_acknowledge)
{
	struct lwm2m_ctx ctx;
	struct lwm2m_message msg;

	(void)memset(&ctx, 0x0, sizeof(ctx));

	ctx.processed_req = &msg;
	lwm2m_engine_context_init(&ctx);
	lwm2m_acknowledge(&ctx);
	lwm2m_engine_context_close(&ctx);

	zassert_equal(coap_packet_init_fake.call_count, 1, "COAP packet not initialized");
	zassert_equal(engine_update_tx_time_fake.call_count, 1, "TX time not updated");
}

ZTEST(lwm2m_message_handling, test_lwm2m_parse_peerinfo)
{
	int ret;
	struct lwm2m_ctx ctx;
	char url[] = "coaps://my_host.io:5684";

	(void)memset(&ctx, 0x0, sizeof(ctx));
	lwm2m_engine_context_init(&ctx);

	http_parser_parse_url_fake.custom_fake = parse_url;
	ret = lwm2m_parse_peerinfo(url, &ctx, false);
	zassert_equal(ret, 0);
	lwm2m_engine_context_close(&ctx);
}

ZTEST(lwm2m_message_handling, test_lwm2m_parse_peerinfo_fail)
{
	int ret;
	struct lwm2m_ctx ctx;
	char url[] = "coap://my_host.io:5684";

	(void)memset(&ctx, 0x0, sizeof(ctx));
	lwm2m_engine_context_init(&ctx);

	http_parser_parse_url_fake.return_val = -1;
	ret = lwm2m_parse_peerinfo(url, &ctx, false);
	zassert_equal(ret, -ENOTSUP);

	http_parser_parse_url_fake.custom_fake = parse_url;
	ret = lwm2m_parse_peerinfo(url, &ctx, false);
	zassert_equal(ret, -EPROTONOSUPPORT);
	lwm2m_engine_context_close(&ctx);
}

ZTEST(lwm2m_message_handling, test_register_payload_handler)
{
	int ret;
	struct lwm2m_message msg;
	struct lwm2m_engine_obj obj;
	struct lwm2m_engine_obj_inst obj_inst;

	(void)memset(&msg, 0x0, sizeof(msg));

	obj.obj_id = MY_OBJ_ID;
	obj.instance_count = 1U;
	obj_inst.obj = &obj;
	obj_inst.obj_inst_id = MY_OBJ_INST_ID;
	sys_slist_append(&my_obj_list, &obj.node);
	sys_slist_append(&my_obj_inst_list, &obj_inst.node);
	msg.path = LWM2M_OBJ(MY_OBJ_ID, MY_OBJ_INST_ID);
	msg.out.writer = &my_writer;
	ret = lwm2m_register_payload_handler(&msg);
	zassert_equal(ret, 0);
}

ZTEST(lwm2m_message_handling, test_lwm2m_send)
{
	int ret;
	struct lwm2m_ctx ctx;
	struct lwm2m_obj_path path_list[2];

	path_list[0] = LWM2M_OBJ(MY_OBJ_ID, MY_OBJ_INST_ID);
	path_list[1] = LWM2M_OBJ(MY_OBJ_ID, MY_OBJ_INST_ID, 0);
	(void)memset(&ctx, 0x0, sizeof(ctx));

	lwm2m_engine_context_init(&ctx);
	lwm2m_rd_client_is_registred_fake.return_val = true;
	ret = lwm2m_send(&ctx, path_list, 2, false);

	lwm2m_engine_context_close(&ctx);
	
	zassert_equal(coap_packet_append_option_fake.call_count, 1, "COAP option not appended to the packet");
}

ZTEST(lwm2m_message_handling, test_lwm2m_perform_composite_read_op)
{
	int ret;
	struct lwm2m_message msg;
	sys_slist_t path_list;
	struct lwm2m_obj_path_list entry;
	struct coap_packet out_pkt;
	struct lwm2m_engine_obj obj;
	struct lwm2m_engine_obj_inst obj_inst;
	struct lwm2m_engine_res resources;
	struct lwm2m_engine_res_inst res_inst;
	struct lwm2m_engine_obj_field obj_field[] = {
		OBJ_FIELD(1U, R, OPAQUE), OBJ_FIELD(1U, R, STRING), OBJ_FIELD(1U, R, U8),
		OBJ_FIELD(1U, R, U16),	  OBJ_FIELD(1U, R, U32),    OBJ_FIELD(1U, R, S8),
		OBJ_FIELD(1U, R, S16),	  OBJ_FIELD(1U, R, S32),    OBJ_FIELD(1U, R, S64),
		OBJ_FIELD(1U, R, TIME),	  OBJ_FIELD(1U, R, BOOL),   OBJ_FIELD(1U, R, FLOAT),
		OBJ_FIELD(1U, R, OBJLNK)};
	uint32_t data;

	sys_slist_init(&path_list);
	(void)memset(&msg, 0x0, sizeof(msg));
	(void)memset(&resources, 0x0, sizeof(resources));

	entry.path = LWM2M_OBJ(MY_OBJ_ID, MY_OBJ_INST_ID);
	sys_slist_append(&path_list, &entry.node);
	msg.out.out_cpkt = &out_pkt;
	msg.out.writer = &my_writer;
	obj.obj_id = MY_OBJ_ID;
	obj.fields = obj_field;
	obj_inst.obj = &obj;
	obj_inst.obj_inst_id = MY_OBJ_INST_ID;
	res_inst.data_ptr = &data;
	res_inst.data_len = sizeof(data);
	res_inst.max_data_len = sizeof(data);
	resources.res_instances = &res_inst;
	resources.res_inst_count = 1U;
	obj_inst.resources = &resources;
	obj_inst.resource_count = 1U;
	get_engine_obj_inst_fake.return_val = &obj_inst;

	for (int i = 0; i < sizeof(obj_field) / sizeof(obj_field[0]); i++) {
		lwm2m_get_engine_obj_field_fake.return_val = &obj_field[i];
		ret = lwm2m_perform_composite_read_op(&msg, LWM2M_FORMAT_APP_SENML_CBOR,
						      &path_list);
		zassert_equal(ret, 0);
	}

	zassert_equal(put_opaque_fake.call_count, 1, "Resource data opaque not read.");
	zassert_equal(put_string_fake.call_count, 1, "Resource data string not read.");
	zassert_equal(put_s64_fake.call_count, 2, "Resource data s64 not read.");
	zassert_equal(put_s32_fake.call_count, 2, "Resource data s32 not read.");
	zassert_equal(put_s16_fake.call_count, 2, "Resource data s16 not read.");
	zassert_equal(put_s8_fake.call_count, 1, "Resource data s8 not read.");
	zassert_equal(put_time_fake.call_count, 1, "Resource data time not read.");
	zassert_equal(put_bool_fake.call_count, 1, "Resource data bool not read.");
	zassert_equal(put_float_fake.call_count, 1, "Resource data float not read.");
	zassert_equal(put_objlnk_fake.call_count, 1, "Resource data objlnk not read.");
}

ZTEST(lwm2m_message_handling, test_lwm2m_perform_read_op)
{
	int ret;
	struct lwm2m_message msg;
	struct lwm2m_engine_obj obj;
	struct lwm2m_engine_res resources;
	struct lwm2m_engine_obj_inst obj_inst;
	struct coap_packet out_pkt;

	(void)memset(&msg, 0x0, sizeof(msg));

	obj.obj_id = MY_OBJ_ID;
	obj.instance_count = 1U;
	obj_inst.obj = &obj;
	obj_inst.obj_inst_id = MY_OBJ_INST_ID;
	obj_inst.resources = &resources;
	obj_inst.resource_count = 1U;

	msg.path = LWM2M_OBJ(MY_OBJ_ID, MY_OBJ_INST_ID);
	msg.out.writer = &my_writer;
	msg.out.out_cpkt = &out_pkt;

	get_engine_obj_inst_fake.return_val = &obj_inst;
	ret = lwm2m_perform_read_op(&msg, LWM2M_FORMAT_APP_SENML_CBOR);
	zassert_equal(ret, 0);
}

ZTEST(lwm2m_message_handling, test_do_composite_read_op_for_parsed_list)
{
	int ret;
	struct lwm2m_message msg;
	sys_slist_t path_list;

	ret = do_composite_read_op_for_parsed_list(&msg, LWM2M_FORMAT_APP_SEML_JSON, &path_list);
	zassert_equal(ret, 0);

	ret = do_composite_read_op_for_parsed_list(&msg, LWM2M_FORMAT_APP_SENML_CBOR, &path_list);
	zassert_equal(ret, 0);

	ret = do_composite_read_op_for_parsed_list(&msg, LWM2M_FORMAT_APP_CBOR, &path_list);
	zassert_equal(ret, -ENOMSG);
}
#endif

ZTEST(lwm2m_message_handling, test_lwm2m_write_handler)
{
	int ret;
	struct lwm2m_message msg;
	struct lwm2m_engine_obj_inst obj_inst;
	struct lwm2m_engine_res res;
	struct lwm2m_engine_res_inst res_inst;
	struct lwm2m_engine_obj_field obj_field[] = {
		OBJ_FIELD(1U, R, TIME),	 OBJ_FIELD(1U, R, OPAQUE), OBJ_FIELD(1U, R, STRING),
		OBJ_FIELD(1U, R, U8),	 OBJ_FIELD(1U, R, U16),	   OBJ_FIELD(1U, R, U32),
		OBJ_FIELD(1U, R, S8),	 OBJ_FIELD(1U, R, S16),	   OBJ_FIELD(1U, R, S32),
		OBJ_FIELD(1U, R, S64),	 OBJ_FIELD(1U, R, BOOL),   OBJ_FIELD(1U, R, FLOAT),
		OBJ_FIELD(1U, R, OBJLNK)};
	int64_t data;

	(void)memset(&res, 0x0, sizeof(res));
	(void)memset(&res_inst, 0x0, sizeof(res_inst));
	(void)memset(&msg, 0x0, sizeof(msg));

	res_inst.data_ptr = &data;
	res_inst.max_data_len = sizeof(data);
	res_inst.data_len = sizeof(data);

	msg.in.reader = &my_reader;

	for (int i = 0; i < sizeof(obj_field) / sizeof(obj_field[0]); i++) {
		if (i == 0) {
			res_inst.max_data_len = sizeof(time_t);
		}
		ret = lwm2m_write_handler(&obj_inst, &res, &res_inst, &obj_field[i], &msg);
		zassert_equal(ret, 0);
	}

	zassert_equal(lwm2m_notify_observer_path_fake.call_count, 13, "Notify observer not called");
	zassert_equal(get_string_fake.call_count, 1, "Resource data string not read.");
	zassert_equal(get_s64_fake.call_count, 2, "Resource data s64 not read.");
	zassert_equal(get_s32_fake.call_count, 5, "Resource data s32 not read.");
	zassert_equal(get_time_fake.call_count, 1, "Resource data time not read.");
	zassert_equal(get_bool_fake.call_count, 1, "Resource data bool not read.");
	zassert_equal(get_float_fake.call_count, 1, "Resource data float not read.");
	zassert_equal(get_objlnk_fake.call_count, 1, "Resource data objlnk not read.");
}
