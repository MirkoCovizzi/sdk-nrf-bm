/*
 * Copyright (c) 2025 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */
#include <unity.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <zephyr/sys/util.h>

/* #include "mock_cmock_pm_evt_handlers_security_manager.h" */

#include "cmock_ble.h"
#include "cmock_ble_gap.h"
#include "cmock_ble_conn_state.h"
#include "cmock_id_manager.h"
#include "cmock_peer_database.h"
#include "cmock_peer_data_storage.h"
#include "cmock_security_dispatcher.h"
#include "cmock_mocks.h"

#include <bluetooth/peer_manager/peer_manager_types.h>
#include <modules/security_manager.h>
#define MAX_EVT_HANDLER_CALLS 1000

#define USER_FLAG1 1
#define USER_FLAG2 2
#define USER_FLAG3 3
#define USER_FLAG4 4

extern bool m_module_initialized;
extern ble_gap_sec_params_t m_sec_params;
extern ble_gap_sec_params_t *mp_sec_params;
extern bool m_sec_params_set;

#if CONFIG_PM_LESC_ENABLED == 0
extern ble_gap_lesc_p256_pk_t *m_p_public_key;
#endif

extern int m_flag_link_secure_pending_busy;
extern int m_flag_link_secure_force_repairing;
extern int m_flag_link_secure_null_params;
extern int m_flag_params_reply_pending_busy;

extern void sm_pdb_evt_handler(pm_evt_t *p_event);
extern void pm_sm_evt_handler(pm_evt_t *p_sm_evt);
extern void sm_smd_evt_handler(pm_evt_t *p_event);

typedef struct {
	/* The security parameters to use in the call to the security_dispatcher */
	ble_gap_sec_params_t *p_sec_params;
	/* The buffer for holding the security parameters. */
	ble_gap_sec_params_t sec_params_mem;
	/* Whether @ref sm_sec_params_reply has been called for this context instance. */
	bool params_reply_called;
} sec_params_reply_context_t;

static uint16_t m_arbitrary_conn_handle = 11;
static pm_peer_id_t m_arbitrary_peer_id = 3;
static ble_gap_sec_params_t m_arbitrary_sec_params = {
	1, 0, 0, 0, BLE_GAP_IO_CAPS_NONE, 0, 7, 16, {1, 0, 0, 0}, {1, 0, 0, 0}};
static ble_gap_sec_params_t m_arbitrary_alternate_sec_params = {
	0, 0, 0, 0, BLE_GAP_IO_CAPS_KEYBOARD_DISPLAY, 0, 7, 16, {0, 0, 0, 0}, {0, 0, 0, 0}};
static ble_gap_sec_params_t m_wrong_sec_params = {
	0, 0, 0, 0, BLE_GAP_IO_CAPS_KEYBOARD_DISPLAY, 0, 7, 17, {0, 0, 0, 0}, {0, 0, 0, 0}};

static uint16_t m_arbitrary_flag_id_link_secure_busy = USER_FLAG1;
static uint16_t m_arbitrary_flag_id_force_repairing = USER_FLAG2;
static uint16_t m_arbitrary_flag_id_params_reply_busy = USER_FLAG3;
static uint16_t m_arbitrary_flag_id_null_params = USER_FLAG4;

static pm_peer_data_id_t m_arbitrary_data_id = PM_PEER_DATA_ID_BONDING;
static ble_gap_lesc_p256_pk_t *m_p_arbitrary_pk = (ble_gap_lesc_p256_pk_t *)0x20002345;

pm_evt_t m_expected_events[MAX_EVT_HANDLER_CALLS];
int m_n_expected_events;

static void evt_handler_call_record_clear(void)
{
	m_n_expected_events = 0;
}

void test_init(void)
{
	uint32_t err_code;

#if PM_LESC_ENABLED == 1
	nrf_ble_lesc_init_ExpectAndReturn(NRF_SUCCESS);
#endif

	/* Init success. */
	err_code = sm_init();
	TEST_ASSERT_EQUAL_UINT(NRF_SUCCESS, err_code);
}

static void sm_sec_params_set_test(bool bond, bool mitm, uint8_t io_caps, bool oob,
				   uint8_t min_key_size, uint8_t max_key_size, bool kdist_own_enc,
				   bool kdist_own_id, bool kdist_own_sign, bool kdist_own_link,
				   bool kdist_peer_enc, bool kdist_peer_id, bool kdist_peer_sign,
				   bool kdist_peer_link, uint32_t expected_err_code)
{
	uint32_t err_code;
	ble_gap_sec_params_t sec_params = {.bond = bond,
					   .mitm = mitm,
					   .io_caps = io_caps,
					   .oob = oob,
					   .min_key_size = min_key_size,
					   .max_key_size = max_key_size,
					   .kdist_own = {

							   .enc = kdist_own_enc,
							   .id = kdist_own_id,
							   .sign = kdist_own_sign,
							   .link = kdist_own_link,
						   },
					   .kdist_peer = {
						   .enc = kdist_peer_enc,
						   .id = kdist_peer_id,
						   .sign = kdist_peer_sign,
						   .link = kdist_peer_link,
					   }};

	err_code = sm_sec_params_set(&sec_params);
	TEST_ASSERT_EQUAL(expected_err_code, err_code);
}

void __cmock_sm_conn_sec_status_get_expect(bool bonded, bool connected, bool encrypted, bool mitm,
					   bool lesc)
{
	static uint8_t alternating;

	__cmock_ble_conn_state_status_ExpectAndReturn(m_arbitrary_conn_handle,
						      connected ? BLE_CONN_STATUS_CONNECTED
								: BLE_CONN_STATUS_DISCONNECTED);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(
		m_arbitrary_conn_handle, bonded ? m_arbitrary_peer_id : PM_PEER_ID_INVALID);
	__cmock_ble_conn_state_encrypted_ExpectAndReturn(m_arbitrary_conn_handle, encrypted);
	__cmock_ble_conn_state_mitm_protected_ExpectAndReturn(m_arbitrary_conn_handle, mitm);
	__cmock_ble_conn_state_lesc_ExpectAndReturn(m_arbitrary_conn_handle, lesc && alternating);
	if (!(lesc && alternating)) /* 'alternating' reflects that LESC can be true from two */
				    /* different sources. */
	{
		static pm_peer_data_bonding_t bonding_data;
		static pm_peer_data_t returned_peer_data;

		memset(&returned_peer_data, 0, sizeof(pm_peer_data_t));
		bonding_data.own_ltk.enc_info.lesc = lesc;
		returned_peer_data.data_id = PM_PEER_DATA_ID_BONDING;
		returned_peer_data.p_bonding_data = &bonding_data;

		__cmock_ble_conn_state_encrypted_ExpectAndReturn(m_arbitrary_conn_handle,
								 encrypted);
		if (encrypted) {
			__cmock_pds_peer_data_read_ExpectAndReturn(
				bonded ? m_arbitrary_peer_id : PM_PEER_ID_INVALID,
				PM_PEER_DATA_ID_BONDING, NULL, NULL, NRF_SUCCESS);
			__cmock_pds_peer_data_read_IgnoreArg_p_data();
			__cmock_pds_peer_data_read_ReturnThruPtr_p_data(
				&returned_peer_data);
			__cmock_pds_peer_data_read_IgnoreArg_p_buf_len();
		}
	}
	alternating = (alternating + 1) % 2;
}

void test_sm_conn_sec_status_get(void)
{
	pm_conn_sec_status_t conn_sec_status;
	uint32_t err_code;

	pm_peer_data_bonding_t bonding_data = {.own_ltk = {.enc_info = {.lesc = true}}};
	pm_peer_data_flash_t returned_peer_data;

	memset(&returned_peer_data, 0, sizeof(pm_peer_data_flash_t));
	returned_peer_data.data_id = PM_PEER_DATA_ID_BONDING;
	returned_peer_data.p_bonding_data = &bonding_data;

	__cmock_ble_conn_state_status_ExpectAndReturn(m_arbitrary_conn_handle,
						      BLE_CONN_STATUS_INVALID);
	err_code = sm_conn_sec_status_get(m_arbitrary_conn_handle, &conn_sec_status);

	TEST_ASSERT_EQUAL(BLE_ERROR_INVALID_CONN_HANDLE, err_code);

	__cmock_sm_conn_sec_status_get_expect(true, false, false, true, true);

	err_code = sm_conn_sec_status_get(m_arbitrary_conn_handle, &conn_sec_status);

	TEST_ASSERT_EQUAL(NRF_SUCCESS, err_code);
	TEST_ASSERT_EQUAL_UINT(true, conn_sec_status.bonded);
	TEST_ASSERT_EQUAL_UINT(false, conn_sec_status.connected);
	TEST_ASSERT_EQUAL_UINT(false, conn_sec_status.encrypted);
	TEST_ASSERT_EQUAL_UINT(true, conn_sec_status.mitm_protected);
	TEST_ASSERT_EQUAL_UINT(false, conn_sec_status.lesc);

	__cmock_sm_conn_sec_status_get_expect(true, true, true, true, true);

	err_code = sm_conn_sec_status_get(m_arbitrary_conn_handle, &conn_sec_status);

	TEST_ASSERT_EQUAL(NRF_SUCCESS, err_code);
	TEST_ASSERT_EQUAL_UINT(true, conn_sec_status.bonded);
	TEST_ASSERT_EQUAL_UINT(true, conn_sec_status.connected);
	TEST_ASSERT_EQUAL_UINT(true, conn_sec_status.encrypted);
	TEST_ASSERT_EQUAL_UINT(true, conn_sec_status.mitm_protected);
	TEST_ASSERT_EQUAL_UINT(true, conn_sec_status.lesc);

	__cmock_sm_conn_sec_status_get_expect(false, true, true, false, false);

	err_code = sm_conn_sec_status_get(m_arbitrary_conn_handle, &conn_sec_status);

	TEST_ASSERT_EQUAL(NRF_SUCCESS, err_code);
	TEST_ASSERT_EQUAL_UINT(false, conn_sec_status.bonded);
	TEST_ASSERT_EQUAL_UINT(true, conn_sec_status.connected);
	TEST_ASSERT_EQUAL_UINT(true, conn_sec_status.encrypted);
	TEST_ASSERT_EQUAL_UINT(false, conn_sec_status.mitm_protected);
	TEST_ASSERT_EQUAL_UINT(false, conn_sec_status.lesc);
}

void test_sm_sec_is_sufficient(void)
{
	pm_conn_sec_status_t conn_sec_status_req;
	bool result;

	pm_peer_data_bonding_t bonding_data = {.own_ltk = {.enc_info = {.lesc = true}}};
	pm_peer_data_flash_t returned_peer_data;

	memset(&returned_peer_data, 0, sizeof(pm_peer_data_flash_t));
	returned_peer_data.data_id = PM_PEER_DATA_ID_BONDING;
	returned_peer_data.p_bonding_data = &bonding_data;

	__cmock_ble_conn_state_status_ExpectAndReturn(m_arbitrary_conn_handle,
						      BLE_CONN_STATUS_INVALID);
	result = sm_sec_is_sufficient(m_arbitrary_conn_handle, &conn_sec_status_req);

	TEST_ASSERT_FALSE(result);

	conn_sec_status_req.bonded = true;
	conn_sec_status_req.connected = false;
	conn_sec_status_req.encrypted = false;
	conn_sec_status_req.mitm_protected = true;
	conn_sec_status_req.lesc = true;

	__cmock_sm_conn_sec_status_get_expect(true, false, false, true, true);
	result = sm_sec_is_sufficient(m_arbitrary_conn_handle, &conn_sec_status_req);
	TEST_ASSERT(result);
	/* TODO fixme
	 * __cmock_sm_conn_sec_status_get_expect(true, true, true, true, true);
	 * result = sm_sec_is_sufficient(m_arbitrary_conn_handle, &conn_sec_status_req);
	 * TEST_ASSERT(result);
	 */
	__cmock_sm_conn_sec_status_get_expect(true, false, false, false, true);
	result = sm_sec_is_sufficient(m_arbitrary_conn_handle, &conn_sec_status_req);
	TEST_ASSERT_FALSE(result);
	__cmock_sm_conn_sec_status_get_expect(true, false, false, true, false);
	result = sm_sec_is_sufficient(m_arbitrary_conn_handle, &conn_sec_status_req);
	TEST_ASSERT_FALSE(result);
	__cmock_sm_conn_sec_status_get_expect(false, false, false, true, true);
	result = sm_sec_is_sufficient(m_arbitrary_conn_handle, &conn_sec_status_req);
	TEST_ASSERT_FALSE(result);

	conn_sec_status_req.bonded = true;
	conn_sec_status_req.connected = true;
	conn_sec_status_req.encrypted = true;
	conn_sec_status_req.mitm_protected = true;
	conn_sec_status_req.lesc = true;

	/* TODO fixme
	 * __cmock_sm_conn_sec_status_get_expect(true, true, true, true, true);
	 * result = sm_sec_is_sufficient(m_arbitrary_conn_handle, &conn_sec_status_req);
	 * TEST_ASSERT(result);
	 */
	conn_sec_status_req.bonded = false;
	conn_sec_status_req.connected = true;
	conn_sec_status_req.encrypted = true;
	conn_sec_status_req.mitm_protected = false;
	conn_sec_status_req.lesc = false;

	__cmock_sm_conn_sec_status_get_expect(false, true, true, false, false);
	result = sm_sec_is_sufficient(m_arbitrary_conn_handle, &conn_sec_status_req);
	TEST_ASSERT(result);
	__cmock_sm_conn_sec_status_get_expect(false, false, true, false, false);
	result = sm_sec_is_sufficient(m_arbitrary_conn_handle, &conn_sec_status_req);
	TEST_ASSERT_FALSE(result);
	__cmock_sm_conn_sec_status_get_expect(false, true, false, false, false);
	result = sm_sec_is_sufficient(m_arbitrary_conn_handle, &conn_sec_status_req);
	TEST_ASSERT_FALSE(result);
}

void test_sm_sec_params_set(void)
{
	uint32_t err_code;
	const uint8_t IO_NONE = BLE_GAP_IO_CAPS_NONE;

	err_code = sm_sec_params_set(NULL);
	TEST_ASSERT_EQUAL(NRF_SUCCESS, err_code);

	/* MITM and bond independent */
	sm_sec_params_set_test(false, false, IO_NONE, 0, 7, 16, 0, 0, 0, 0, 0, 0, 0, 0,
			       NRF_SUCCESS);
	sm_sec_params_set_test(true, true, IO_NONE, 1, 7, 16, 1, 0, 0, 0, 0, 0, 0, 0, NRF_SUCCESS);
	sm_sec_params_set_test(true, false, IO_NONE, 0, 7, 16, 1, 0, 0, 0, 0, 0, 0, 0, NRF_SUCCESS);
	sm_sec_params_set_test(false, true, IO_NONE, 1, 7, 16, 0, 0, 0, 0, 0, 0, 0, 0, NRF_SUCCESS);

	/* OOB and bond independent. */
	sm_sec_params_set_test(false, 1, BLE_GAP_IO_CAPS_DISPLAY_ONLY, false, 7, 16, 0, 0, 0, 0, 0,
			       0, 0, 0, NRF_SUCCESS);
	sm_sec_params_set_test(false, 1, IO_NONE, true, 7, 16, 0, 0, 0, 0, 0, 0, 0, 0, NRF_SUCCESS);

	/* No keydist if no bond. */
	sm_sec_params_set_test(true, 0, IO_NONE, 0, 7, 16, true, 0, 0, 0, 0, 0, 0, 0, NRF_SUCCESS);
	sm_sec_params_set_test(false, 0, IO_NONE, 0, 7, 16, true, 0, 0, 0, 0, 0, 0, 0,
			       NRF_ERROR_INVALID_PARAM);
	sm_sec_params_set_test(false, 0, IO_NONE, 0, 7, 16, 0, true, 0, 0, 0, 0, 0, 0,
			       NRF_ERROR_INVALID_PARAM);
	sm_sec_params_set_test(false, 0, IO_NONE, 0, 7, 16, 0, 0, 0, 0, true, 0, 0, 0,
			       NRF_ERROR_INVALID_PARAM);
	sm_sec_params_set_test(false, 0, IO_NONE, 0, 7, 16, 0, 0, 0, 0, 0, true, 0, 0,
			       NRF_ERROR_INVALID_PARAM);

	/* keydist if bond. */
	sm_sec_params_set_test(true, 0, IO_NONE, 0, 7, 16, true, true, false, false, true, true,
			       false, false, NRF_SUCCESS);
	sm_sec_params_set_test(true, 0, IO_NONE, 0, 7, 16, false, false, false, false, false, false,
			       false, false, NRF_ERROR_INVALID_PARAM);

	/* Never sign in keydist. */
	sm_sec_params_set_test(true, 0, IO_NONE, 0, 7, 16, 1, 0, false, 0, 0, 0, false, 0,
			       NRF_SUCCESS);
	sm_sec_params_set_test(true, 0, IO_NONE, 0, 7, 16, 1, 0, true, 0, 0, 0, false, 0,
			       NRF_ERROR_INVALID_PARAM);
	sm_sec_params_set_test(true, 0, IO_NONE, 0, 7, 16, 1, 0, false, 0, 0, 0, true, 0,
			       NRF_ERROR_INVALID_PARAM);

	/* Never link in keydist. */
	sm_sec_params_set_test(true, 0, IO_NONE, 0, 7, 16, 1, 0, 0, false, 0, 0, 0, false,
			       NRF_SUCCESS);
	sm_sec_params_set_test(true, 0, IO_NONE, 0, 7, 16, 1, 0, 0, true, 0, 0, 0, false,
			       NRF_ERROR_INVALID_PARAM);
	sm_sec_params_set_test(true, 0, IO_NONE, 0, 7, 16, 1, 0, 0, false, 0, 0, 0, true,
			       NRF_ERROR_INVALID_PARAM);

	/* No OOB if no MITM. */
	sm_sec_params_set_test(1, true, IO_NONE, true, 7, 16, 1, 0, 0, 0, 0, 0, 0, 0, NRF_SUCCESS);
	sm_sec_params_set_test(1, false, IO_NONE, false, 7, 16, 1, 0, 0, 0, 0, 0, 0, 0,
			       NRF_SUCCESS);
	sm_sec_params_set_test(1, true, BLE_GAP_IO_CAPS_DISPLAY_ONLY, false, 7, 16, 1, 0, 0, 0, 0,
			       0, 0, 0, NRF_SUCCESS);
	sm_sec_params_set_test(1, false, IO_NONE, true, 7, 16, 1, 0, 0, 0, 0, 0, 0, 0,
			       NRF_ERROR_INVALID_PARAM);

	/* 7 <= min_keysize <= max_keysize <= 16 */
	sm_sec_params_set_test(1, 0, IO_NONE, 0, 7, 16, 1, 0, 0, 0, 0, 0, 0, 0, NRF_SUCCESS);
	sm_sec_params_set_test(1, 0, IO_NONE, 0, 16, 16, 1, 0, 0, 0, 0, 0, 0, 0, NRF_SUCCESS);
	sm_sec_params_set_test(1, 0, IO_NONE, 0, 7, 7, 1, 0, 0, 0, 0, 0, 0, 0, NRF_SUCCESS);
	sm_sec_params_set_test(1, 0, IO_NONE, 0, 6, 16, 1, 0, 0, 0, 0, 0, 0, 0,
			       NRF_ERROR_INVALID_PARAM);
	sm_sec_params_set_test(1, 0, IO_NONE, 0, 7, 17, 1, 0, 0, 0, 0, 0, 0, 0,
			       NRF_ERROR_INVALID_PARAM);
	sm_sec_params_set_test(1, 0, IO_NONE, 0, 16, 15, 1, 0, 0, 0, 0, 0, 0, 0,
			       NRF_ERROR_INVALID_PARAM);

	/* IO Capabilities must be one of the valid values. */
	sm_sec_params_set_test(1, 1, BLE_GAP_IO_CAPS_DISPLAY_ONLY, 1, 7, 16, 1, 0, 0, 0, 0, 0, 0, 0,
			       NRF_SUCCESS);
	sm_sec_params_set_test(1, 1, BLE_GAP_IO_CAPS_DISPLAY_YESNO, 1, 7, 16, 1, 0, 0, 0, 0, 0, 0,
			       0, NRF_SUCCESS);
	sm_sec_params_set_test(1, 1, BLE_GAP_IO_CAPS_KEYBOARD_ONLY, 1, 7, 16, 1, 0, 0, 0, 0, 0, 0,
			       0, NRF_SUCCESS);
	sm_sec_params_set_test(1, 1, BLE_GAP_IO_CAPS_NONE, 1, 7, 16, 1, 0, 0, 0, 0, 0, 0, 0,
			       NRF_SUCCESS);
	sm_sec_params_set_test(1, 1, BLE_GAP_IO_CAPS_KEYBOARD_DISPLAY, 1, 7, 16, 1, 0, 0, 0, 0, 0,
			       0, 0, NRF_SUCCESS);
	sm_sec_params_set_test(1, 1, BLE_GAP_IO_CAPS_KEYBOARD_DISPLAY + 1, 1, 7, 16, 1, 0, 0, 0, 0,
			       0, 0, 0, NRF_ERROR_INVALID_PARAM);
	sm_sec_params_set_test(1, 1, 0xFF, 1, 7, 16, 1, 0, 0, 0, 0, 0, 0, 0,
			       NRF_ERROR_INVALID_PARAM);

	/* Must have either IO caps or OOB if MITM */
	sm_sec_params_set_test(1, true, BLE_GAP_IO_CAPS_DISPLAY_ONLY, false, 7, 16, 1, 0, 0, 0, 0,
			       0, 0, 0, NRF_SUCCESS);
	sm_sec_params_set_test(1, true, BLE_GAP_IO_CAPS_NONE, false, 7, 16, 1, 0, 0, 0, 0, 0, 0, 0,
			       NRF_ERROR_INVALID_PARAM);
	sm_sec_params_set_test(1, false, BLE_GAP_IO_CAPS_NONE, false, 7, 16, 1, 0, 0, 0, 0, 0, 0, 0,
			       NRF_SUCCESS);
	sm_sec_params_set_test(1, true, BLE_GAP_IO_CAPS_NONE, true, 7, 16, 1, 0, 0, 0, 0, 0, 0, 0,
			       NRF_SUCCESS);
}

#define TEST_ASSERT_EQUAL_PARAMS(struct_name, member_name)                                         \
	TEST_ASSERT_EQUAL(m_expected_events[index].params.struct_name.member_name,                 \
			  p_sm_evt->params.struct_name.member_name)
#define TEST_ASSERT_EQUAL_MEMORY_PARAMS(struct_name, member_name)                                  \
	TEST_ASSERT_EQUAL_MEMORY(&m_expected_events[index].params.struct_name.member_name,         \
				 sizeof(p_sm_evt->params.struct_name.member_name),                 \
				 &p_sm_evt->params.struct_name.member_name)
#define TEST_ASSERT_EQUAL_PTR_PARAMS(struct_name, member_name)                                     \
	TEST_ASSERT_EQUAL_PTR(m_expected_events[index].params.struct_name.member_name,             \
			      p_sm_evt->params.struct_name.member_name)

static void sm_evt_check(uint32_t index, pm_evt_t const *p_sm_evt)
{
	TEST_ASSERT_NOT_NULL(p_sm_evt);
	TEST_ASSERT_EQUAL_UINT(m_expected_events[index].evt_id, p_sm_evt->evt_id);
	TEST_ASSERT_EQUAL_UINT(m_expected_events[index].conn_handle, p_sm_evt->conn_handle);
	switch (p_sm_evt->evt_id) {
	case PM_EVT_CONN_SEC_PARAMS_REQ:
		TEST_ASSERT_EQUAL_PTR_PARAMS(conn_sec_params_req, p_peer_params);
		break;
	case PM_EVT_SLAVE_SECURITY_REQ:
#ifdef CONFIG_SOFTDEVICE_CENTRAL
		TEST_ASSERT_EQUAL_PARAMS(slave_security_req, bond);
		TEST_ASSERT_EQUAL_PARAMS(slave_security_req, mitm);
#endif
		break;
	case PM_EVT_CONN_SEC_SUCCEEDED:
		TEST_ASSERT_EQUAL_PARAMS(conn_sec_succeeded, procedure);
		TEST_ASSERT_EQUAL_PARAMS(conn_sec_succeeded, data_stored);
		break;
	case PM_EVT_CONN_SEC_FAILED:
		TEST_ASSERT_EQUAL_PARAMS(conn_sec_failed, procedure);
		TEST_ASSERT_EQUAL_PARAMS(conn_sec_failed, error);
		TEST_ASSERT_EQUAL_PARAMS(conn_sec_failed, error_src);
		break;
	case PM_EVT_ERROR_UNEXPECTED:
		TEST_ASSERT_EQUAL_PARAMS(error_unexpected, error);
		break;
	default:
		break;
	}
}

#undef TEST_ASSERT_EQUAL_PARAMS
#undef TEST_ASSERT_EQUAL_MEMORY_PARAMS
#undef TEST_ASSERT_EQUAL_PTR_PARAMS

static void sm_evt_handler_stub(pm_evt_t *p_evt, int numcalls)
{
	uint32_t err_code;

	sm_evt_check(numcalls, p_evt);

	if (p_evt->evt_id == PM_EVT_CONN_SEC_PARAMS_REQ) {
		switch (numcalls % 3) {
		case 0:
			/* Don't reply. */
			break;
		case 1:
			/* Reply with alternative sec_params */
			err_code = sm_sec_params_reply(p_evt->conn_handle,
						       &m_arbitrary_alternate_sec_params,
						       p_evt->params.conn_sec_params_req.p_context);
			TEST_ASSERT_EQUAL(NRF_SUCCESS, err_code);
			break;
		case 2:
			/* Reply with NULL */
			err_code = sm_sec_params_reply(p_evt->conn_handle, NULL,
						       p_evt->params.conn_sec_params_req.p_context);
			TEST_ASSERT_EQUAL(NRF_SUCCESS, err_code);
			break;
		default:
			/* Should never happen. */
			break;
		}
	}
}

static int sm_evt_expect(bool expect_event, pm_evt_t *p_expected_sm_evt)
{
	if (expect_event) {
		m_expected_events[m_n_expected_events++] = *p_expected_sm_evt;
		__cmock_pm_sm_evt_handler_Stub(sm_evt_handler_stub);
	}
	return m_n_expected_events - 1;
}

static ble_gap_sec_params_t *params_req_expect(bool expect_event, uint16_t conn_handle,
					       ble_gap_sec_params_t *p_set_sec_params)
{
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(conn_handle, m_arbitrary_peer_id);
	pm_evt_t params_req_evt = {.evt_id = PM_EVT_CONN_SEC_PARAMS_REQ,
				   .conn_handle = conn_handle,
				   .peer_id = m_arbitrary_peer_id};
	switch (sm_evt_expect(expect_event, &params_req_evt) % 3) {
	case 0:
		return p_set_sec_params;
	case 1:
		return &m_arbitrary_alternate_sec_params;
	case 2:
		return NULL;
	default:
		/* Should never happen. */
		return &m_wrong_sec_params;
	}
}

static ble_gap_sec_params_t *sm_link_secure_test_setup(uint16_t conn_handle,
						       uint32_t expected_err_code_smd,
						       ble_gap_sec_params_t *p_expected_sec_params,
						       bool busy, bool force_repairing,
						       bool null_params)
{

	if (null_params) {
		__cmock_smd_link_secure_ExpectAndReturn(conn_handle, NULL, force_repairing,
							expected_err_code_smd);
	} else {
		p_expected_sec_params = params_req_expect(true, conn_handle, p_expected_sec_params);
		__cmock_smd_link_secure_ExpectWithArrayAndReturn(
			conn_handle, p_expected_sec_params, (p_expected_sec_params != NULL),
			force_repairing, expected_err_code_smd);
	}

	if (expected_err_code_smd == NRF_ERROR_BUSY) {
		__cmock_ble_conn_state_user_flag_set_Expect(
			conn_handle, m_arbitrary_flag_id_link_secure_busy, true);
		__cmock_ble_conn_state_user_flag_set_Expect(
			conn_handle, m_arbitrary_flag_id_null_params, null_params);
		__cmock_ble_conn_state_user_flag_set_Expect(
			conn_handle, m_arbitrary_flag_id_force_repairing, force_repairing);
	} else {
		__cmock_ble_conn_state_user_flag_set_Expect(
			conn_handle, m_arbitrary_flag_id_link_secure_busy, false);
	}

	return p_expected_sec_params;
}

static void sm_link_secure_test(uint32_t expected_err_code_smd, bool busy,
				uint32_t expected_err_code)
{
	uint32_t err_code;
	static bool force_repairing;

	force_repairing = !force_repairing; /* Alternate to try both. */

	(void)sm_link_secure_test_setup(m_arbitrary_conn_handle, expected_err_code_smd,
					&m_arbitrary_sec_params, busy, force_repairing, false);

	err_code = sm_link_secure(m_arbitrary_conn_handle, force_repairing);
	TEST_ASSERT_EQUAL(expected_err_code, err_code);
}

void test_sm_link_secure(void)
{
	uint32_t err_code;

	(void)params_req_expect(true, m_arbitrary_conn_handle, &m_arbitrary_sec_params);
	err_code = sm_link_secure(m_arbitrary_conn_handle, false);
	TEST_ASSERT_EQUAL(NRF_ERROR_NOT_FOUND,
			  err_code); /* No reply, and no set, so return NRF_ERROR_NOT_FOUND. */

	sm_link_secure_test(NRF_SUCCESS, false,
			    NRF_SUCCESS); /* Reply, so should not return NRF_ERROR_NOT_FOUND. */
	sm_link_secure_test(NRF_SUCCESS, false,
			    NRF_SUCCESS); /* Reply, so should not return NRF_ERROR_NOT_FOUND. */

	err_code = sm_sec_params_set(&m_arbitrary_sec_params);
	TEST_ASSERT_EQUAL(NRF_SUCCESS, err_code);

	sm_link_secure_test(
		NRF_SUCCESS, false,
		NRF_SUCCESS); /* No reply, but set, so should not return NRF_ERROR_NOT_FOUND. */

	sm_link_secure_test(NRF_ERROR_NULL, false, NRF_ERROR_INTERNAL); /* Unexpected error. */
	sm_link_secure_test(NRF_ERROR_INVALID_STATE, false,
			    NRF_ERROR_INVALID_STATE); /* Unexpected error. */
	sm_link_secure_test(NRF_ERROR_INVALID_PARAM, false,
			    NRF_ERROR_INTERNAL);			    /* Unexpected error. */
	sm_link_secure_test(NRF_ERROR_INTERNAL, false, NRF_ERROR_INTERNAL); /* Unexpected error. */
	sm_link_secure_test(NRF_ERROR_NO_MEM, false, NRF_ERROR_INTERNAL);   /* Unexpected error. */
	sm_link_secure_test(NRF_ERROR_TIMEOUT, false, NRF_ERROR_TIMEOUT);   /* pass error on. */
	sm_link_secure_test(NRF_ERROR_INVALID_DATA, false,
			    NRF_ERROR_INVALID_DATA); /* pass error on. */
	sm_link_secure_test(BLE_ERROR_INVALID_CONN_HANDLE, false,
			    BLE_ERROR_INVALID_CONN_HANDLE);	/* pass error on. */
	sm_link_secure_test(NRF_ERROR_BUSY, true, NRF_SUCCESS); /* Busy => queued. */
	sm_link_secure_test(NRF_ERROR_BUSY, true, NRF_SUCCESS); /* Busy => queued. */
	sm_link_secure_test(NRF_SUCCESS, false, NRF_SUCCESS);	/* pass error on. */
}

static ble_gap_sec_params_t *smd_params_reply_test_setup(uint16_t conn_handle, bool set_params,
							 bool params_missing, bool set_pk,
							 bool pk_missing, uint8_t role,
							 uint32_t expected_err_code_params_reply)
{
	uint32_t err_code;
	ble_gap_lesc_p256_pk_t *p_public_key = m_p_arbitrary_pk;
	ble_gap_sec_params_t *p_expected_sec_params;

	if (set_params) {
		err_code = sm_sec_params_set(&m_arbitrary_sec_params);
		TEST_ASSERT_EQUAL(NRF_SUCCESS, err_code);
	}

	if (set_pk) {
		err_code = sm_lesc_public_key_set(m_p_arbitrary_pk);
#if PM_LESC_ENABLED == 1
		TEST_ASSERT_EQUAL(NRF_ERROR_FORBIDDEN, err_code);
#else
		TEST_ASSERT_EQUAL(NRF_SUCCESS, err_code);
#endif
	}

	if (pk_missing) {
		p_public_key = NULL;
	}

	if (params_missing) {
		p_expected_sec_params = NULL;
	} else {
		p_expected_sec_params = &m_arbitrary_sec_params;
	}

	p_expected_sec_params = params_req_expect(true, conn_handle, p_expected_sec_params);

#if PM_LESC_ENABLED == 1
	nrf_ble_lesc_public_key_get_ExpectAndReturn(p_public_key);
#endif
	__cmock_smd_params_reply_ExpectAndReturn(conn_handle, p_expected_sec_params, p_public_key,
						 expected_err_code_params_reply);

	if (expected_err_code_params_reply == NRF_ERROR_BUSY) {
		__cmock_ble_conn_state_user_flag_set_Expect(
			conn_handle, m_arbitrary_flag_id_params_reply_busy, true);
		__cmock_ble_conn_state_user_flag_set_Expect(
			conn_handle, m_arbitrary_flag_id_link_secure_busy, false);
	} else {
		__cmock_ble_conn_state_user_flag_set_Expect(
			conn_handle, m_arbitrary_flag_id_params_reply_busy, false);
		__cmock_ble_conn_state_user_flag_set_Expect(
			conn_handle, m_arbitrary_flag_id_link_secure_busy, false);
	}

	return p_expected_sec_params;
}

static void smd_evt_handler_PARAMS_REQ_test(bool set_params, bool expect_event,
					    pm_evt_id_t expected_event, bool params_missing,
					    bool set_pk, bool pk_missing, uint8_t role,
					    uint32_t expected_err_code_params_reply)
{
	pm_evt_t smd_evt = {
		.evt_id = PM_EVT_CONN_SEC_PARAMS_REQ,
		.conn_handle = m_arbitrary_conn_handle,
	};

	pm_evt_t sm_evt = {
		.evt_id = expected_event,
		.conn_handle = m_arbitrary_conn_handle,
		.peer_id = m_arbitrary_peer_id,
	};

	ble_gap_sec_params_t *p_expected_sec_params = smd_params_reply_test_setup(
		m_arbitrary_conn_handle, set_params, params_missing, set_pk, pk_missing, role,
		expected_err_code_params_reply);

	if (expected_event == PM_EVT_ERROR_UNEXPECTED) {
		sm_evt.params.error_unexpected.error = expected_err_code_params_reply;
	} else if (expected_event == PM_EVT_CONN_SEC_FAILED) {
		sm_evt.params.conn_sec_failed.procedure = p_expected_sec_params->bond
								  ? PM_CONN_SEC_PROCEDURE_BONDING
								  : PM_CONN_SEC_PROCEDURE_PAIRING;
		sm_evt.params.conn_sec_failed.error = PM_CONN_SEC_ERROR_SMP_TIMEOUT;
		sm_evt.params.conn_sec_failed.error_src = BLE_GAP_SEC_STATUS_SOURCE_LOCAL;
	}

	if (expect_event) {
		__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle,
								      m_arbitrary_peer_id);
	}

	(void)sm_evt_expect(expect_event, &sm_evt);
	sm_smd_evt_handler(&smd_evt);
}

#ifdef CONFIG_SOFTDEVICE_CENTRAL
static void smd_evt_handler_SLAVE_SECURITY_REQUEST_test(bool sec_req_bond, bool sec_req_mitm,
							bool sec_req_lesc, bool bond, bool mitm,
							bool lesc, bool encrypted,
							bool force_repairing, bool reject_sec_req)
{

	pm_evt_t smd_evt = {
		.evt_id = PM_EVT_SLAVE_SECURITY_REQ,
		.conn_handle = m_arbitrary_conn_handle,

		.params.slave_security_req = {

				.bond = sec_req_bond,
				.mitm = sec_req_mitm,
				.lesc = sec_req_lesc,
			},
	};

	pm_evt_t sm_evt = {
		.evt_id = PM_EVT_SLAVE_SECURITY_REQ,
		.conn_handle = m_arbitrary_conn_handle,
		.peer_id = m_arbitrary_peer_id,
		.params.slave_security_req = {

				.bond = sec_req_bond,
				.mitm = sec_req_mitm,
				.lesc = sec_req_lesc,

			},
	};

	if (!reject_sec_req) {
		(void)sm_sec_params_set(&m_arbitrary_sec_params);
		__cmock_ble_conn_state_encrypted_ExpectAndReturn(m_arbitrary_conn_handle,
								 encrypted);
		if (encrypted) {
			__cmock_sm_conn_sec_status_get_expect(bond, true, true, mitm, lesc);
		}
	}

	(void)sm_link_secure_test_setup(m_arbitrary_conn_handle, NRF_SUCCESS,
					reject_sec_req ? NULL : &m_arbitrary_sec_params, false,
					force_repairing, reject_sec_req);
	(void)sm_evt_expect(true, &sm_evt);

	sm_smd_evt_handler(&smd_evt);
}
#endif

static void smd_evt_handler_OTHER_test(pm_evt_id_t evt_id)
{

	pm_evt_t smd_evt = {
		.evt_id = evt_id,
	};

	__cmock_pm_sm_evt_handler_Expect(&smd_evt);
	sm_smd_evt_handler(&smd_evt);
}

void test_smd_evt_handler_PARAMS_REQ_1(void)
{
	smd_evt_handler_PARAMS_REQ_test(false, false, PM_EVT_ERROR_UNEXPECTED, true, false, true,
					BLE_GAP_ROLE_PERIPH, NRF_SUCCESS);
	smd_evt_handler_PARAMS_REQ_test(true, false, PM_EVT_ERROR_UNEXPECTED, false, true, false,
					BLE_GAP_ROLE_PERIPH, NRF_ERROR_INVALID_STATE);
	smd_evt_handler_PARAMS_REQ_test(false, true, PM_EVT_ERROR_UNEXPECTED, false, false, false,
					BLE_GAP_ROLE_PERIPH, NRF_ERROR_INVALID_PARAM);
	smd_evt_handler_PARAMS_REQ_test(true, true, PM_EVT_CONN_SEC_FAILED, false, false, false,
					BLE_GAP_ROLE_PERIPH, NRF_ERROR_TIMEOUT);
	smd_evt_handler_PARAMS_REQ_test(true, true, PM_EVT_ERROR_UNEXPECTED, false, true, false,
					BLE_GAP_ROLE_PERIPH, BLE_ERROR_INVALID_CONN_HANDLE);
	smd_evt_handler_PARAMS_REQ_test(true, false, PM_EVT_ERROR_UNEXPECTED, false, false, false,
					BLE_GAP_ROLE_PERIPH, NRF_ERROR_BUSY);
	smd_evt_handler_PARAMS_REQ_test(true, false, PM_EVT_ERROR_UNEXPECTED, false, false, false,
					BLE_GAP_ROLE_PERIPH, NRF_SUCCESS);
}

void test_smd_evt_handler_SLAVE_SECURITY_REQUEST(void)
{
#ifdef CONFIG_SOFTDEVICE_CENTRAL
	/* No params set => reject. */
	smd_evt_handler_SLAVE_SECURITY_REQUEST_test(false, false, false, false, false, false, true,
						    false, true);
	/* No params set => reject. */
	smd_evt_handler_SLAVE_SECURITY_REQUEST_test(false, false, false, true, false, false, true,
						    false, true);
	/* Not encrypted */
	smd_evt_handler_SLAVE_SECURITY_REQUEST_test(false, false, false, true, false, false, false,
						    false, false);
	/* No bond/MITM requested nor provided. */
	smd_evt_handler_SLAVE_SECURITY_REQUEST_test(false, false, false, false, false, false, true,
						    false,
						    false);
	/* Require bond.  Bond not provided => repair. */
	smd_evt_handler_SLAVE_SECURITY_REQUEST_test(
		true, false, false, false, false, false, true, true,
		false);
	/* Require bond. Bond provided. */
	smd_evt_handler_SLAVE_SECURITY_REQUEST_test(true, false, false, true, false, false, true,
						    false, false);
	/* Require MITM. MITM not provided => repair. */
	smd_evt_handler_SLAVE_SECURITY_REQUEST_test(
		true, true, false, true, false, false, true, true,
		false);
	/* Require MITM. MITM provided. */
	smd_evt_handler_SLAVE_SECURITY_REQUEST_test(true, true, false, true, true, false, true,
						    false, false);
	/* Require bond/MITM. Bond/MITM provided. */
	smd_evt_handler_SLAVE_SECURITY_REQUEST_test(
		true, true, false, true, true, false, true, false,
		false);
	/* Require LESC. LESC not provided => repair. */
	smd_evt_handler_SLAVE_SECURITY_REQUEST_test(
		true, true, true, true, true, false, true, true,
		false);
	/* Require LESC. LESC provided. */
	smd_evt_handler_SLAVE_SECURITY_REQUEST_test(true, true, true, true, true, true, true, false,
						    false);
	/* More provided than required. */
	smd_evt_handler_SLAVE_SECURITY_REQUEST_test(true, false, false, true, true, false, true,
						    false, false);
	/* More provided than required. */
	smd_evt_handler_SLAVE_SECURITY_REQUEST_test(false, false, false, true, true, false, true,
						    false, false);
	/* More provided than required. */
	smd_evt_handler_SLAVE_SECURITY_REQUEST_test(false, false, false, true, false, false, true,
						    false, false);
#endif
}

void test_smd_evt_handler_OTHER(void)
{
	smd_evt_handler_OTHER_test(PM_EVT_CONN_SEC_START);
	smd_evt_handler_OTHER_test(PM_EVT_CONN_SEC_SUCCEEDED);
	smd_evt_handler_OTHER_test(PM_EVT_CONN_SEC_FAILED);
	smd_evt_handler_OTHER_test(PM_EVT_ERROR_UNEXPECTED);
}

static void params_pending_process(uint16_t conn_handle, uint16_t flag_id, bool pending,
				   uint32_t expected_err_code, bool expect_event,
				   pm_evt_id_t expected_event)
{
	if (pending) {
		ble_gap_sec_params_t *p_expected_sec_params =
			smd_params_reply_test_setup(conn_handle, true, false, true, false,
						    BLE_GAP_ROLE_PERIPH, expected_err_code);
		pm_evt_t sm_evt = {
			.evt_id = expected_event,
			.conn_handle = conn_handle,
			.peer_id = m_arbitrary_peer_id,
		};

		if (expected_event == PM_EVT_ERROR_UNEXPECTED) {
			sm_evt.params.error_unexpected.error = expected_err_code;
		} else if (expected_event == PM_EVT_CONN_SEC_FAILED) {
			sm_evt.params.conn_sec_failed.procedure =
				(p_expected_sec_params != NULL) && p_expected_sec_params->bond
					? PM_CONN_SEC_PROCEDURE_BONDING
					: PM_CONN_SEC_PROCEDURE_PAIRING;
			sm_evt.params.conn_sec_failed.error = PM_CONN_SEC_ERROR_SMP_TIMEOUT;
			sm_evt.params.conn_sec_failed.error_src = BLE_GAP_SEC_STATUS_SOURCE_LOCAL;
		}

		if (expect_event) {
			__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(conn_handle,
									      m_arbitrary_peer_id);
		}
		(void)sm_evt_expect(expect_event, &sm_evt);
	}
}

static void secure_pending_process(uint16_t conn_handle, uint16_t flag_id, bool pending,
				   bool force_repairing, bool null_params,
				   uint32_t expected_err_code, bool expect_event,
				   pm_evt_id_t expected_event)
{
	if (pending) {
		__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(
			conn_handle, m_arbitrary_flag_id_force_repairing, force_repairing);
		__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(
			conn_handle, m_arbitrary_flag_id_null_params, null_params);
		ble_gap_sec_params_t *p_expected_sec_params = sm_link_secure_test_setup(
			conn_handle, expected_err_code, &m_arbitrary_sec_params,
			(expected_err_code == NRF_ERROR_BUSY), force_repairing, null_params);
		pm_evt_t sm_evt = {
			.evt_id = expected_event,
			.conn_handle = conn_handle,
			.peer_id = m_arbitrary_peer_id,
		};

		if (expected_event == PM_EVT_ERROR_UNEXPECTED) {
			sm_evt.params.error_unexpected.error = expected_err_code;
		} else if (expected_event == PM_EVT_CONN_SEC_FAILED) {
			sm_evt.params.conn_sec_failed.procedure =
				(p_expected_sec_params != NULL) && p_expected_sec_params->bond
					? PM_CONN_SEC_PROCEDURE_BONDING
					: PM_CONN_SEC_PROCEDURE_PAIRING;
			sm_evt.params.conn_sec_failed.error = PM_CONN_SEC_ERROR_SMP_TIMEOUT;
			sm_evt.params.conn_sec_failed.error_src = BLE_GAP_SEC_STATUS_SOURCE_LOCAL;
		}

		if (expect_event) {
			__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(conn_handle,
									      m_arbitrary_peer_id);
		}
		(void)sm_evt_expect(expect_event, &sm_evt);
	}
}

static uint32_t
ble_conn_state_for_each_set_user_flag_stub(uint16_t flag_index,
					   ble_conn_state_user_function_t user_function, void *ctx,
					   int cmock_num_calls)
{
	TEST_ASSERT_NULL(ctx);
	for (uint16_t i = 0; i < 8; i++) {
		user_function(i, ctx);
	}
	return 8;
}

static void pending_actions_process_test(bool do_params_pending, bool do_link_secure)
{
	uint16_t flag_id_params_reply = m_arbitrary_flag_id_params_reply_busy;
	uint16_t flag_id_link_secure = m_arbitrary_flag_id_link_secure_busy;

	__cmock_ble_conn_state_for_each_set_user_flag_Stub(
		ble_conn_state_for_each_set_user_flag_stub);

	if (do_params_pending) {
		params_pending_process(0, flag_id_params_reply, true, NRF_SUCCESS, false,
				       PM_EVT_ERROR_UNEXPECTED);
		params_pending_process(1, flag_id_params_reply, true, NRF_ERROR_INVALID_STATE,
				       false, PM_EVT_ERROR_UNEXPECTED);
		params_pending_process(2, flag_id_params_reply, true, NRF_ERROR_INVALID_PARAM, true,
				       PM_EVT_ERROR_UNEXPECTED);
		params_pending_process(3, flag_id_params_reply, true, BLE_ERROR_INVALID_CONN_HANDLE,
				       true, PM_EVT_ERROR_UNEXPECTED);
		params_pending_process(4, flag_id_params_reply, true, NRF_ERROR_NO_MEM, true,
				       PM_EVT_ERROR_UNEXPECTED);
		params_pending_process(5, flag_id_params_reply, true, NRF_ERROR_BUSY, false,
				       PM_EVT_ERROR_UNEXPECTED);
		params_pending_process(6, flag_id_params_reply, true, NRF_ERROR_TIMEOUT, true,
				       PM_EVT_CONN_SEC_FAILED);
		params_pending_process(7, flag_id_params_reply, true, NRF_SUCCESS, false,
				       PM_EVT_ERROR_UNEXPECTED);
	}

	if (do_link_secure) {
		uint32_t err_code = sm_sec_params_set(&m_arbitrary_sec_params);

		TEST_ASSERT_EQUAL(NRF_SUCCESS, err_code);

		secure_pending_process(0, flag_id_link_secure, true, true, true, NRF_SUCCESS, false,
				       PM_EVT_ERROR_UNEXPECTED);
		secure_pending_process(1, flag_id_link_secure, true, true, false,
				       NRF_ERROR_INVALID_STATE, false, PM_EVT_ERROR_UNEXPECTED);
		secure_pending_process(2, flag_id_link_secure, true, false, true,
				       NRF_ERROR_INVALID_PARAM, true, PM_EVT_ERROR_UNEXPECTED);
		secure_pending_process(3, flag_id_link_secure, true, false, false,
				       BLE_ERROR_INVALID_CONN_HANDLE, true,
				       PM_EVT_ERROR_UNEXPECTED);
		secure_pending_process(4, flag_id_link_secure, true, true, true, NRF_ERROR_NULL,
				       true, PM_EVT_ERROR_UNEXPECTED);
		secure_pending_process(5, flag_id_link_secure, true, false, true, NRF_ERROR_NO_MEM,
				       true, PM_EVT_ERROR_UNEXPECTED);
		secure_pending_process(6, flag_id_link_secure, true, true, false, NRF_ERROR_BUSY,
				       false, PM_EVT_ERROR_UNEXPECTED);
		secure_pending_process(7, flag_id_link_secure, true, false, false,
				       NRF_ERROR_TIMEOUT, true, PM_EVT_CONN_SEC_FAILED);
	}
}

static void pdb_evt_handler_test(pm_evt_id_t evt_id, bool process_busy)
{
	pm_evt_t evt = {
		.evt_id = evt_id,
		.peer_id = m_arbitrary_peer_id,
	};

	if (evt_id == PM_EVT_PEER_DATA_UPDATE_SUCCEEDED) {
		evt.params.peer_data_update_succeeded.data_id = m_arbitrary_data_id;
	} else if (evt_id == PM_EVT_PEER_DATA_UPDATE_FAILED) {
		evt.params.peer_data_update_failed.data_id = m_arbitrary_data_id;
	}

	if (process_busy) {
		pending_actions_process_test(true, true);
	}

	sm_pdb_evt_handler(&evt);
}

void test_pdb_evt_handler(void)
{
	pdb_evt_handler_test(PM_EVT_PEER_DATA_UPDATE_SUCCEEDED, true);
	pdb_evt_handler_test(PM_EVT_PEER_DATA_UPDATE_FAILED, true);
	pdb_evt_handler_test(PM_EVT_PEER_DELETE_SUCCEEDED, true);
	pdb_evt_handler_test(PM_EVT_PEER_DELETE_FAILED, true);
	pdb_evt_handler_test(PM_EVT_FLASH_GARBAGE_COLLECTED, true);
	pdb_evt_handler_test(PM_EVT_STORAGE_FULL, false);
	pdb_evt_handler_test(PM_EVT_ERROR_UNEXPECTED, false);
}

static void sm_ble_evt_handler_test(uint16_t ble_evt_id)
{
	ble_evt_t ble_evt;

	ble_evt.header.evt_id = ble_evt_id;
	__cmock_smd_ble_evt_handler_Expect(&ble_evt);

#if PM_LESC_ENABLED == 1
	__cmock_nrf_ble_lesc_on_ble_evt_Expect(&ble_evt);
#endif

	pending_actions_process_test(true, true);

	sm_ble_evt_handler(&ble_evt);
}

void test_sm_ble_evt_handler(void)
{
	sm_ble_evt_handler_test(BLE_GAP_EVT_CONNECTED);
	sm_ble_evt_handler_test(BLE_GAP_EVT_CONN_SEC_UPDATE);
	sm_ble_evt_handler_test(BLE_GATTS_EVT_WRITE);
}

void test_sm_conn_sec_config_reply(void)
{
	pm_conn_sec_config_t config;

	config.allow_repairing = true;
	__cmock_smd_conn_sec_config_reply_Expect(m_arbitrary_conn_handle, &config);
	sm_conn_sec_config_reply(m_arbitrary_conn_handle, &config);

	config.allow_repairing = false;
	__cmock_smd_conn_sec_config_reply_Expect(m_arbitrary_conn_handle, &config);
	sm_conn_sec_config_reply(m_arbitrary_conn_handle, &config);
}

void test_sm_params_reply(void)
{
	sec_params_reply_context_t dummy_context = {0};
	uint32_t err_code;

	err_code = sm_sec_params_reply(m_arbitrary_conn_handle, &m_arbitrary_sec_params, NULL);
	TEST_ASSERT_EQUAL(NRF_ERROR_NULL, err_code);

	err_code =
		sm_sec_params_reply(m_arbitrary_conn_handle, &m_wrong_sec_params, &dummy_context);
	TEST_ASSERT_EQUAL(NRF_ERROR_INVALID_PARAM, err_code);
}

void tearDown(void)
{
	m_module_initialized = false;
	mp_sec_params = NULL;
	m_sec_params_set = false;
	memset(&m_sec_params, 0x00, sizeof(m_sec_params));

#if PM_LESC_ENABLED != 1
	m_p_public_key = NULL;
#endif

	m_flag_link_secure_pending_busy = CONFIG_BLE_CONN_STATE_USER_FLAG_COUNT;
	m_flag_link_secure_force_repairing = CONFIG_BLE_CONN_STATE_USER_FLAG_COUNT;
	m_flag_link_secure_null_params = CONFIG_BLE_CONN_STATE_USER_FLAG_COUNT;
	m_flag_params_reply_pending_busy = CONFIG_BLE_CONN_STATE_USER_FLAG_COUNT;
}

void setUp(void)
{
	evt_handler_call_record_clear();

#if PM_LESC_ENABLED == 1
	nrf_ble_lesc_init_ExpectAndReturn(NRF_SUCCESS);
#endif

	__cmock_ble_conn_state_user_flag_acquire_ExpectAndReturn(
		m_arbitrary_flag_id_link_secure_busy);
	__cmock_ble_conn_state_user_flag_acquire_ExpectAndReturn(
		m_arbitrary_flag_id_force_repairing);
	__cmock_ble_conn_state_user_flag_acquire_ExpectAndReturn(m_arbitrary_flag_id_null_params);
	__cmock_ble_conn_state_user_flag_acquire_ExpectAndReturn(
		m_arbitrary_flag_id_params_reply_busy);

	(void)sm_init();

	/* Suppress "Symbol not accessed" lint warnings. */
	(void)m_module_initialized;
	(void)m_sec_params;
	(void)m_sec_params_set;
	(void)mp_sec_params;
#if PM_LESC_ENABLED != 1
	(void)m_p_public_key;
#endif
	(void)m_flag_link_secure_null_params;
	(void)m_flag_link_secure_force_repairing;
	(void)m_flag_link_secure_pending_busy;
	(void)m_flag_params_reply_pending_busy;
}

extern int unity_main(void);

int main(void)
{
	return unity_main();
}
