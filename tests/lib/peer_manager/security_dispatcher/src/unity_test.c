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

#include "cmock_ble.h"
#include "cmock_ble_gap.h"
#include "cmock_ble_conn_state.h"
#include "cmock_peer_data_storage.h"
#include "cmock_peer_database.h"
#include "cmock_id_manager.h"
#include <modules/peer_manager_types.h>
#include <ble_qwr.h>

#include <modules/security_dispatcher.h>

#define SMD_EVENT_HANDLERS_CNT 1
/*ARRAY_SIZE(m_evt_handlers) */

#define MAX_EVT_HANDLER_CALLS       (20)

#define USER_FLAG1 1
#define USER_FLAG2 2
#define USER_FLAG3 3
#define USER_FLAG5 5

extern pm_evt_handler_internal_t const m_evt_handlers[];
extern bool m_module_initialized;
extern int m_flag_sec_proc;
extern int m_flag_sec_proc_pairing;
extern int m_flag_sec_proc_bonding;
extern int m_flag_allow_repairing;
extern ble_gap_lesc_p256_pk_t m_peer_pk;

static uint32_t                      m_n_evt_handler_calls;

static uint16_t                      m_arbitrary_conn_handle = 11;
static pm_peer_id_t                  m_arbitrary_peer_id = 3;
static ble_gap_master_id_t           m_arbitrary_master_id;
static ble_gap_sec_params_t          m_arbitrary_sec_params;
static pm_peer_data_bonding_t        m_arbitrary_bonding_data;
static uint16_t m_arbitrary_flag_id_sec_proc = USER_FLAG1;
static uint16_t m_arbitrary_flag_id_pairing  = USER_FLAG2;
static uint16_t m_arbitrary_flag_id_bonding  = USER_FLAG3;
static uint16_t m_arbitrary_flag_id_allow    = USER_FLAG5;
static ble_gap_lesc_p256_pk_t      *m_p_arbitrary_pk = (ble_gap_lesc_p256_pk_t *)0x20001234;
static bool                          m_reject_pairing = true;

static pm_evt_t m_evt_handler_records[MAX_EVT_HANDLER_CALLS];


void evt_handler_call_record_clear(void)
{
	m_n_evt_handler_calls = 0;
}


void sm_smd_evt_handler(pm_evt_t *p_event)
{
	m_evt_handler_records[m_n_evt_handler_calls++] = *p_event;
	if ((p_event->evt_id == PM_EVT_CONN_SEC_CONFIG_REQ) && !m_reject_pairing) {
		pm_conn_sec_config_t config = {.allow_repairing = !m_reject_pairing};

		smd_conn_sec_config_reply(p_event->conn_handle, &config);
	}
}

void gcm_smd_evt_handler(pm_evt_t *p_event)
{
	m_evt_handler_records[m_n_evt_handler_calls++] = *p_event;
}


void sec_params_req_ble_evt_get(ble_evt_t *p_ble_evt, uint16_t conn_handle)
{
	memset(p_ble_evt, 0, sizeof(ble_evt_t));
	p_ble_evt->header.evt_id  = BLE_GAP_EVT_SEC_PARAMS_REQUEST;
	p_ble_evt->header.evt_len = sizeof(ble_gap_evt_t);

	p_ble_evt->evt.gap_evt.conn_handle = conn_handle;
}


void test_init(void)
{
	uint32_t err;

	/* Reset module static data (undo setUp()). */
	tearDown();

	/* __cmock_ble_conn_state_user_flag_acquire error. */
	__cmock_ble_conn_state_user_flag_acquire_ExpectAndReturn(-ENOSPC);
	__cmock_ble_conn_state_user_flag_acquire_ExpectAndReturn(-ENOSPC);
	__cmock_ble_conn_state_user_flag_acquire_ExpectAndReturn(-ENOSPC);
	__cmock_ble_conn_state_user_flag_acquire_ExpectAndReturn(-ENOSPC);
	err = smd_init();
	TEST_ASSERT_EQUAL_UINT32(NRF_ERROR_INTERNAL, err);

	tearDown();

	/* __cmock_ble_conn_state_user_flag_acquire error. */
	__cmock_ble_conn_state_user_flag_acquire_ExpectAndReturn(m_arbitrary_flag_id_sec_proc);
	__cmock_ble_conn_state_user_flag_acquire_ExpectAndReturn(-ENOSPC);
	__cmock_ble_conn_state_user_flag_acquire_ExpectAndReturn(-ENOSPC);
	__cmock_ble_conn_state_user_flag_acquire_ExpectAndReturn(-ENOSPC);
	err = smd_init();
	TEST_ASSERT_EQUAL_UINT32(NRF_ERROR_INTERNAL, err);

	tearDown();

	/* __cmock_ble_conn_state_user_flag_acquire error. */
	__cmock_ble_conn_state_user_flag_acquire_ExpectAndReturn(m_arbitrary_flag_id_sec_proc);
	__cmock_ble_conn_state_user_flag_acquire_ExpectAndReturn(m_arbitrary_flag_id_pairing);
	__cmock_ble_conn_state_user_flag_acquire_ExpectAndReturn(-ENOSPC);
	__cmock_ble_conn_state_user_flag_acquire_ExpectAndReturn(-ENOSPC);
	err = smd_init();
	TEST_ASSERT_EQUAL_UINT32(NRF_ERROR_INTERNAL, err);

	tearDown();

	/* __cmock_ble_conn_state_user_flag_acquire error. */
	__cmock_ble_conn_state_user_flag_acquire_ExpectAndReturn(m_arbitrary_flag_id_sec_proc);
	__cmock_ble_conn_state_user_flag_acquire_ExpectAndReturn(m_arbitrary_flag_id_pairing);
	__cmock_ble_conn_state_user_flag_acquire_ExpectAndReturn(m_arbitrary_flag_id_bonding);
	__cmock_ble_conn_state_user_flag_acquire_ExpectAndReturn(-ENOSPC);
	err = smd_init();
	TEST_ASSERT_EQUAL_UINT32(NRF_ERROR_INTERNAL, err);

	tearDown();

	/* Init success. */
	__cmock_ble_conn_state_user_flag_acquire_ExpectAndReturn(m_arbitrary_flag_id_sec_proc);
	__cmock_ble_conn_state_user_flag_acquire_ExpectAndReturn(m_arbitrary_flag_id_pairing);
	__cmock_ble_conn_state_user_flag_acquire_ExpectAndReturn(m_arbitrary_flag_id_bonding);
	__cmock_ble_conn_state_user_flag_acquire_ExpectAndReturn(m_arbitrary_flag_id_allow);
	err = smd_init();
	TEST_ASSERT_EQUAL_UINT32(NRF_SUCCESS, err);
}


static void sec_proc_expect_end(void)
{
	__cmock_ble_conn_state_user_flag_set_Expect(m_arbitrary_conn_handle,
						    m_arbitrary_flag_id_sec_proc, false);
}


static void sec_proc_expect_fail(pm_peer_id_t peer_id)
{
	sec_proc_expect_end();
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, peer_id);
}

#if defined(BLE_GAP_ROLE_CENTRAL)
static void sec_proc_expect_enc(void)
{
	__cmock_ble_conn_state_user_flag_set_Expect(m_arbitrary_conn_handle,
						    m_arbitrary_flag_id_sec_proc, true);
	__cmock_ble_conn_state_user_flag_set_Expect(m_arbitrary_conn_handle,
						    m_arbitrary_flag_id_pairing,  false);
	__cmock_ble_conn_state_user_flag_set_Expect(m_arbitrary_conn_handle,
						    m_arbitrary_flag_id_bonding,  false);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle,
							      m_arbitrary_peer_id);
}


static void sec_proc_expect_pairing(bool bonding_proc, pm_peer_id_t peer_id)
{
	__cmock_ble_conn_state_user_flag_set_Expect(m_arbitrary_conn_handle,
						    m_arbitrary_flag_id_sec_proc, true);
	__cmock_ble_conn_state_user_flag_set_Expect(m_arbitrary_conn_handle,
						    m_arbitrary_flag_id_pairing,  true);
	__cmock_ble_conn_state_user_flag_set_Expect(m_arbitrary_conn_handle,
						    m_arbitrary_flag_id_bonding,  bonding_proc);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, peer_id);
}
#endif

void test_params_reply(void)
{
	uint32_t err;

	pm_peer_data_t returned_peer_data;

	memset(&returned_peer_data, 0, sizeof(pm_peer_data_t));
	returned_peer_data.data_id        = PM_PEER_DATA_ID_BONDING;
	returned_peer_data.p_bonding_data = &m_arbitrary_bonding_data;

	ble_gap_sec_params_t sec_params_bonding = {.bond = true, .mitm = false};
	ble_gap_sec_params_t sec_params_pairing = {.bond = false, .mitm = false};

	ble_gap_sec_keyset_t expected_keyset = {

	.keys_own = {

		.p_enc_key  = &m_arbitrary_bonding_data.own_ltk,
		.p_id_key   = NULL,
		.p_sign_key = NULL,
		.p_pk       = m_p_arbitrary_pk,
	},
	.keys_peer = {

		.p_enc_key  = &m_arbitrary_bonding_data.peer_ltk,
		.p_id_key   = &m_arbitrary_bonding_data.peer_ble_id,
		.p_sign_key = NULL,
		.p_pk       = &m_peer_pk,
	}
	};


	ble_gap_sec_keyset_t expected_keyset_pairing = {

	.keys_own = {

		.p_enc_key  = NULL,
		.p_id_key   = NULL,
		.p_sign_key = NULL,
		.p_pk       = m_p_arbitrary_pk,
	},
	.keys_peer = {

		.p_enc_key  = NULL,
		.p_id_key   = NULL,
		.p_sign_key = NULL,
		.p_pk       = &m_peer_pk,
	}
	};


	/* No write buffer. Also sec_req not sent. */
	__cmock_ble_conn_state_role_ExpectAndReturn(m_arbitrary_conn_handle,
						    BLE_GAP_ROLE_PERIPH);
	__cmock_ble_conn_state_user_flag_set_Expect(m_arbitrary_conn_handle,
						    m_arbitrary_flag_id_allow, false);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle,
							      m_arbitrary_peer_id);
	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle,
							     m_arbitrary_flag_id_allow, false);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle,
							      m_arbitrary_peer_id);
	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle,
							     m_arbitrary_flag_id_allow, true);
	__cmock_pdb_write_buf_get_ExpectAndReturn(PDB_TEMP_PEER_ID(m_arbitrary_conn_handle),
						  PM_PEER_DATA_ID_BONDING, 1, NULL, NRF_ERROR_BUSY);
	__cmock_pdb_write_buf_get_IgnoreArg_p_peer_data();

	err = smd_params_reply(m_arbitrary_conn_handle, &sec_params_bonding, m_p_arbitrary_pk);

	TEST_ASSERT_EQUAL_UINT32(NRF_ERROR_BUSY, err);
	TEST_ASSERT_EQUAL_UINT32(1 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	TEST_ASSERT_EQUAL_UINT32(PM_EVT_CONN_SEC_CONFIG_REQ, m_evt_handler_records[0].evt_id);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_conn_handle, m_evt_handler_records[0].conn_handle);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_conn_handle, m_evt_handler_records[0].conn_handle);
	evt_handler_call_record_clear();

	/* Invalid parameters */
	__cmock_ble_conn_state_role_ExpectAndReturn(m_arbitrary_conn_handle, BLE_GAP_ROLE_PERIPH);
	__cmock_ble_conn_state_user_flag_set_Expect(m_arbitrary_conn_handle,
						    m_arbitrary_flag_id_allow, false);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle,
							      m_arbitrary_peer_id);
	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle,
							     m_arbitrary_flag_id_allow, true);
	__cmock_pdb_write_buf_get_ExpectAndReturn(PDB_TEMP_PEER_ID(m_arbitrary_conn_handle),
						  PM_PEER_DATA_ID_BONDING, 1, NULL, NRF_SUCCESS);
	__cmock_pdb_write_buf_get_IgnoreArg_p_peer_data();
	__cmock_pdb_write_buf_get_ReturnThruPtr_p_peer_data(&returned_peer_data);
	__cmock_im_ble_addr_get_ExpectAndReturn(
		m_arbitrary_conn_handle,
		&returned_peer_data.p_bonding_data->peer_ble_id.id_addr_info, NRF_SUCCESS);
	__cmock_sd_ble_gap_sec_params_reply_ExpectWithArrayAndReturn(m_arbitrary_conn_handle,
								     BLE_GAP_SEC_STATUS_SUCCESS,
								     &sec_params_bonding, 1,
								     &expected_keyset, 1,
								     NRF_ERROR_INVALID_PARAM);

	err = smd_params_reply(m_arbitrary_conn_handle, &sec_params_bonding, m_p_arbitrary_pk);

	TEST_ASSERT_EQUAL_UINT32(NRF_ERROR_INVALID_PARAM, err);
	TEST_ASSERT_EQUAL_UINT32(0 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	evt_handler_call_record_clear();

	/* No params request pending. */
	__cmock_ble_conn_state_role_ExpectAndReturn(m_arbitrary_conn_handle, BLE_GAP_ROLE_PERIPH);
	__cmock_ble_conn_state_user_flag_set_Expect(m_arbitrary_conn_handle,
						    m_arbitrary_flag_id_allow, false);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle,
							      m_arbitrary_peer_id);
	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle,
							     m_arbitrary_flag_id_allow, true);
	__cmock_pdb_write_buf_get_ExpectAndReturn(PDB_TEMP_PEER_ID(m_arbitrary_conn_handle),
						  PM_PEER_DATA_ID_BONDING, 1, NULL, NRF_SUCCESS);
	__cmock_pdb_write_buf_get_IgnoreArg_p_peer_data();
	__cmock_pdb_write_buf_get_ReturnThruPtr_p_peer_data(&returned_peer_data);
	__cmock_im_ble_addr_get_ExpectAndReturn(
		m_arbitrary_conn_handle,
		&returned_peer_data.p_bonding_data->peer_ble_id.id_addr_info, NRF_SUCCESS);
	__cmock_sd_ble_gap_sec_params_reply_ExpectWithArrayAndReturn(m_arbitrary_conn_handle,
								     BLE_GAP_SEC_STATUS_SUCCESS,
								     &sec_params_bonding, 1,
								     &expected_keyset, 1,
								     NRF_ERROR_INVALID_STATE);

	err = smd_params_reply(m_arbitrary_conn_handle, &sec_params_bonding, m_p_arbitrary_pk);

	TEST_ASSERT_EQUAL_UINT32(NRF_ERROR_INVALID_STATE, err);
	TEST_ASSERT_EQUAL_UINT32(0 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	evt_handler_call_record_clear();

	/* Reject repairing. */
	__cmock_ble_conn_state_role_ExpectAndReturn(m_arbitrary_conn_handle, BLE_GAP_ROLE_PERIPH);
	__cmock_ble_conn_state_user_flag_set_Expect(m_arbitrary_conn_handle,
						    m_arbitrary_flag_id_allow, false);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle,
							      m_arbitrary_peer_id);
	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle,
							     m_arbitrary_flag_id_allow, false);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle,
							      m_arbitrary_peer_id);
	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle,
							     m_arbitrary_flag_id_allow, false);
	__cmock_sd_ble_gap_sec_params_reply_ExpectWithArrayAndReturn(
		m_arbitrary_conn_handle, BLE_GAP_SEC_STATUS_PAIRING_NOT_SUPP, &sec_params_bonding,
		1, NULL, 0, NRF_SUCCESS);
	__cmock_sd_ble_gap_sec_params_reply_IgnoreArg_p_sec_keyset();

	err = smd_params_reply(m_arbitrary_conn_handle, &sec_params_bonding, m_p_arbitrary_pk);

	TEST_ASSERT_EQUAL_UINT32(NRF_SUCCESS, err);
	TEST_ASSERT_EQUAL_UINT32(1 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	TEST_ASSERT_EQUAL_UINT32(PM_EVT_CONN_SEC_CONFIG_REQ, m_evt_handler_records[0].evt_id);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_conn_handle, m_evt_handler_records[0].conn_handle);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_peer_id, m_evt_handler_records[0].peer_id);
	evt_handler_call_record_clear();

	/* Reject repairing - no bonding. */
	__cmock_ble_conn_state_role_ExpectAndReturn(m_arbitrary_conn_handle, BLE_GAP_ROLE_PERIPH);
	__cmock_ble_conn_state_user_flag_set_Expect(m_arbitrary_conn_handle,
						    m_arbitrary_flag_id_allow, false);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle,
							      m_arbitrary_peer_id);
	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle,
							     m_arbitrary_flag_id_allow, false);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle,
							      m_arbitrary_peer_id);
	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle,
							     m_arbitrary_flag_id_allow, false);
	__cmock_sd_ble_gap_sec_params_reply_ExpectWithArrayAndReturn(
		m_arbitrary_conn_handle, BLE_GAP_SEC_STATUS_PAIRING_NOT_SUPP, &sec_params_pairing,
		1, NULL, 0, NRF_SUCCESS);
	__cmock_sd_ble_gap_sec_params_reply_IgnoreArg_p_sec_keyset();

	err = smd_params_reply(m_arbitrary_conn_handle, &sec_params_pairing, m_p_arbitrary_pk);

	TEST_ASSERT_EQUAL_UINT32(NRF_SUCCESS, err);
	TEST_ASSERT_EQUAL_UINT32(1 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	TEST_ASSERT_EQUAL_UINT32(PM_EVT_CONN_SEC_CONFIG_REQ, m_evt_handler_records[0].evt_id);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_conn_handle, m_evt_handler_records[0].conn_handle);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_peer_id, m_evt_handler_records[0].peer_id);
	evt_handler_call_record_clear();

	/* Params request pending. - Peripheral */
	__cmock_ble_conn_state_role_ExpectAndReturn(m_arbitrary_conn_handle, BLE_GAP_ROLE_PERIPH);
	__cmock_ble_conn_state_user_flag_set_Expect(m_arbitrary_conn_handle,
						    m_arbitrary_flag_id_allow, false);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle,
							      m_arbitrary_peer_id);
	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle,
							     m_arbitrary_flag_id_allow, true);
	__cmock_pdb_write_buf_get_ExpectAndReturn(PDB_TEMP_PEER_ID(m_arbitrary_conn_handle),
						  PM_PEER_DATA_ID_BONDING, 1, NULL, NRF_SUCCESS);
	__cmock_pdb_write_buf_get_IgnoreArg_p_peer_data();
	__cmock_pdb_write_buf_get_ReturnThruPtr_p_peer_data(&returned_peer_data);
	__cmock_im_ble_addr_get_ExpectAndReturn(
		m_arbitrary_conn_handle,
		&returned_peer_data.p_bonding_data->peer_ble_id.id_addr_info, NRF_SUCCESS);
	__cmock_sd_ble_gap_sec_params_reply_ExpectWithArrayAndReturn(
		m_arbitrary_conn_handle, BLE_GAP_SEC_STATUS_SUCCESS, &sec_params_bonding, 1,
		&expected_keyset, 1, NRF_SUCCESS);

	err = smd_params_reply(m_arbitrary_conn_handle, &sec_params_bonding, m_p_arbitrary_pk);

	TEST_ASSERT_EQUAL_UINT32(NRF_SUCCESS, err);
	TEST_ASSERT_EQUAL_UINT32(0 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	evt_handler_call_record_clear();
#if defined(BLE_GAP_ROLE_CENTRAL)
	/* Params request pending. - Central */
	__cmock_ble_conn_state_role_ExpectAndReturn(m_arbitrary_conn_handle, BLE_GAP_ROLE_CENTRAL);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle,
							      m_arbitrary_peer_id);
	__cmock_pdb_write_buf_get_ExpectAndReturn(PDB_TEMP_PEER_ID(m_arbitrary_conn_handle),
						  PM_PEER_DATA_ID_BONDING, 1, NULL, NRF_SUCCESS);
	__cmock_pdb_write_buf_get_IgnoreArg_p_peer_data();
	__cmock_pdb_write_buf_get_ReturnThruPtr_p_peer_data(&returned_peer_data);
	__cmock_im_ble_addr_get_ExpectAndReturn(
		m_arbitrary_conn_handle,
		&returned_peer_data.p_bonding_data->peer_ble_id.id_addr_info, NRF_SUCCESS);
	__cmock_sd_ble_gap_sec_params_reply_ExpectWithArrayAndReturn(
		m_arbitrary_conn_handle, BLE_GAP_SEC_STATUS_SUCCESS, NULL, 0, &expected_keyset,
		1, NRF_SUCCESS);

	err = smd_params_reply(m_arbitrary_conn_handle, &sec_params_bonding, m_p_arbitrary_pk);

	TEST_ASSERT_EQUAL_UINT32(NRF_SUCCESS, err);
	TEST_ASSERT_EQUAL_UINT32(0 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	evt_handler_call_record_clear();
#endif

	/* Pairing only - no bonding. */
	__cmock_ble_conn_state_role_ExpectAndReturn(m_arbitrary_conn_handle, BLE_GAP_ROLE_PERIPH);
	__cmock_ble_conn_state_user_flag_set_Expect(m_arbitrary_conn_handle,
						    m_arbitrary_flag_id_allow, false);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle,
							      PM_PEER_ID_INVALID);
	__cmock_sd_ble_gap_sec_params_reply_ExpectWithArrayAndReturn(
		m_arbitrary_conn_handle, BLE_GAP_SEC_STATUS_SUCCESS, &sec_params_pairing, 1,
		&expected_keyset_pairing, 1, NRF_SUCCESS);

	err = smd_params_reply(m_arbitrary_conn_handle, &sec_params_pairing, m_p_arbitrary_pk);

	TEST_ASSERT_EQUAL_UINT32(NRF_SUCCESS, err);
	TEST_ASSERT_EQUAL_UINT32(0 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	evt_handler_call_record_clear();

	#if defined(BLE_GAP_ROLE_CENTRAL)
	/* Reject (PM_BONDING_MODE_NONE) as Central */
	__cmock_ble_conn_state_role_ExpectAndReturn(m_arbitrary_conn_handle, BLE_GAP_ROLE_CENTRAL);
	__cmock_sd_ble_gap_sec_params_reply_ExpectAndReturn(
		m_arbitrary_conn_handle, BLE_GAP_SEC_STATUS_PAIRING_NOT_SUPP, NULL, NULL,
		NRF_SUCCESS);
	__cmock_sd_ble_gap_sec_params_reply_IgnoreArg_p_sec_keyset();

	err = smd_params_reply(m_arbitrary_conn_handle, NULL, NULL);
	TEST_ASSERT_EQUAL_UINT32(NRF_SUCCESS, err);
#endif

	/* Reject (PM_BONDING_MODE_NONE) as Peripheral */
	__cmock_ble_conn_state_role_ExpectAndReturn(m_arbitrary_conn_handle, BLE_GAP_ROLE_PERIPH);
	__cmock_ble_conn_state_user_flag_set_Expect(
		m_arbitrary_conn_handle, m_arbitrary_flag_id_allow, false);
	__cmock_sd_ble_gap_sec_params_reply_ExpectAndReturn(
		m_arbitrary_conn_handle, BLE_GAP_SEC_STATUS_PAIRING_NOT_SUPP, NULL, NULL,
		NRF_SUCCESS);
	__cmock_sd_ble_gap_sec_params_reply_IgnoreArg_p_sec_params();
	__cmock_sd_ble_gap_sec_params_reply_IgnoreArg_p_sec_keyset();

	err = smd_params_reply(m_arbitrary_conn_handle, NULL, NULL);

	TEST_ASSERT_EQUAL_UINT32(NRF_SUCCESS, err);


	/* No existing data in flash, write_buf_get error. */
	__cmock_ble_conn_state_role_ExpectAndReturn(m_arbitrary_conn_handle, BLE_GAP_ROLE_PERIPH);
	__cmock_ble_conn_state_user_flag_set_Expect(
		m_arbitrary_conn_handle, m_arbitrary_flag_id_allow, false);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(
		m_arbitrary_conn_handle, PM_PEER_ID_INVALID);
	__cmock_pdb_write_buf_get_ExpectAndReturn(PDB_TEMP_PEER_ID(
		m_arbitrary_conn_handle), PM_PEER_DATA_ID_BONDING, 1, NULL, NRF_ERROR_BUSY);
	__cmock_pdb_write_buf_get_IgnoreArg_p_peer_data();

	err = smd_params_reply(m_arbitrary_conn_handle, &sec_params_bonding, m_p_arbitrary_pk);

	TEST_ASSERT_EQUAL_UINT32(NRF_ERROR_BUSY, err);

	/* No existing data in flash, SoftDevice error. */
	__cmock_ble_conn_state_role_ExpectAndReturn(m_arbitrary_conn_handle, BLE_GAP_ROLE_PERIPH);
	__cmock_ble_conn_state_user_flag_set_Expect(
		m_arbitrary_conn_handle, m_arbitrary_flag_id_allow, false);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(
		m_arbitrary_conn_handle, PM_PEER_ID_INVALID);
	__cmock_pdb_write_buf_get_ExpectAndReturn(
		PDB_TEMP_PEER_ID(m_arbitrary_conn_handle), PM_PEER_DATA_ID_BONDING, 1, NULL,
		NRF_SUCCESS);
	__cmock_pdb_write_buf_get_IgnoreArg_p_peer_data();
	__cmock_pdb_write_buf_get_ReturnThruPtr_p_peer_data(&returned_peer_data);
	__cmock_im_ble_addr_get_ExpectAndReturn(
		m_arbitrary_conn_handle,
		&returned_peer_data.p_bonding_data->peer_ble_id.id_addr_info, NRF_SUCCESS);
	__cmock_sd_ble_gap_sec_params_reply_ExpectWithArrayAndReturn(
		m_arbitrary_conn_handle, BLE_GAP_SEC_STATUS_SUCCESS, &sec_params_bonding, 1,
		&expected_keyset, 1, NRF_ERROR_INVALID_STATE);

	err = smd_params_reply(m_arbitrary_conn_handle, &sec_params_bonding, m_p_arbitrary_pk);

	TEST_ASSERT_EQUAL_UINT32(NRF_ERROR_INVALID_STATE, err);

	/* No existing data in flash. */
	__cmock_ble_conn_state_role_ExpectAndReturn(m_arbitrary_conn_handle, BLE_GAP_ROLE_PERIPH);
	__cmock_ble_conn_state_user_flag_set_Expect(
		m_arbitrary_conn_handle, m_arbitrary_flag_id_allow, false);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(
		m_arbitrary_conn_handle, PM_PEER_ID_INVALID);
	__cmock_pdb_write_buf_get_ExpectAndReturn(PDB_TEMP_PEER_ID(
		m_arbitrary_conn_handle), PM_PEER_DATA_ID_BONDING, 1, NULL, NRF_SUCCESS);
	__cmock_pdb_write_buf_get_IgnoreArg_p_peer_data();
	__cmock_pdb_write_buf_get_ReturnThruPtr_p_peer_data(&returned_peer_data);
	__cmock_im_ble_addr_get_ExpectAndReturn(
		m_arbitrary_conn_handle,
		&returned_peer_data.p_bonding_data->peer_ble_id.id_addr_info, NRF_SUCCESS);
	__cmock_sd_ble_gap_sec_params_reply_ExpectWithArrayAndReturn(
		m_arbitrary_conn_handle, BLE_GAP_SEC_STATUS_SUCCESS, &sec_params_bonding, 1,
		&expected_keyset, 1, NRF_SUCCESS);

	err = smd_params_reply(m_arbitrary_conn_handle, &sec_params_bonding, m_p_arbitrary_pk);

	TEST_ASSERT_EQUAL_UINT32(NRF_SUCCESS, err);
	TEST_ASSERT_EQUAL_UINT32(BLE_GAP_ROLE_PERIPH, m_arbitrary_bonding_data.own_role);
	TEST_ASSERT_EQUAL_UINT32(0 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	evt_handler_call_record_clear();

#if defined(BLE_GAP_ROLE_CENTRAL)
	/* Central, data exists in flash. */
	__cmock_ble_conn_state_role_ExpectAndReturn(m_arbitrary_conn_handle, BLE_GAP_ROLE_CENTRAL);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(
		m_arbitrary_conn_handle, m_arbitrary_peer_id);
	__cmock_pdb_write_buf_get_ExpectAndReturn(
		PDB_TEMP_PEER_ID(m_arbitrary_conn_handle), PM_PEER_DATA_ID_BONDING, 1, NULL,
		NRF_SUCCESS);
	__cmock_pdb_write_buf_get_IgnoreArg_p_peer_data();
	__cmock_pdb_write_buf_get_ReturnThruPtr_p_peer_data(&returned_peer_data);
	__cmock_im_ble_addr_get_ExpectAndReturn(
		m_arbitrary_conn_handle,
		&returned_peer_data.p_bonding_data->peer_ble_id.id_addr_info, NRF_SUCCESS);
	__cmock_sd_ble_gap_sec_params_reply_ExpectWithArrayAndReturn(
		m_arbitrary_conn_handle, BLE_GAP_SEC_STATUS_SUCCESS, NULL, 0, &expected_keyset, 1,
		NRF_SUCCESS);


	err = smd_params_reply(m_arbitrary_conn_handle, &sec_params_bonding, m_p_arbitrary_pk);

	TEST_ASSERT_EQUAL_UINT32(NRF_SUCCESS, err);
	TEST_ASSERT_EQUAL_UINT32(BLE_GAP_ROLE_CENTRAL, m_arbitrary_bonding_data.own_role);
	TEST_ASSERT_EQUAL_UINT32(0 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	evt_handler_call_record_clear();
#endif
}


void expect_sec_proc_start_evt(
	pm_evt_t *p_pm_evt, pm_conn_sec_procedure_t procedure, pm_peer_id_t peer_id)
{
	TEST_ASSERT_EQUAL_UINT32(PM_EVT_CONN_SEC_START, p_pm_evt->evt_id);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_conn_handle, p_pm_evt->conn_handle);
	TEST_ASSERT_EQUAL_UINT32(procedure, p_pm_evt->params.conn_sec_start.procedure);
	TEST_ASSERT_EQUAL_UINT32(peer_id, p_pm_evt->peer_id);
}


void test_link_secure(void)
{
	uint32_t               err;

#if defined(BLE_GAP_ROLE_CENTRAL)
	ble_gap_sec_params_t sec_params_bonding = {.bond = true, .mitm = false};
	ble_gap_sec_params_t sec_params_pairing = {.bond = false, .mitm = false};
#endif
	pm_peer_data_bonding_t bonding_data     = {.peer_ltk = {.enc_info = {.auth = false}},
						   .own_ltk  = {.enc_info = {.auth = false}}};

	pm_peer_data_flash_t returned_peer_data;

	memset(&returned_peer_data, 0, sizeof(pm_peer_data_flash_t));
	returned_peer_data.data_id        = PM_PEER_DATA_ID_BONDING;
	returned_peer_data.p_bonding_data = &bonding_data;

#if defined(BLE_GAP_ROLE_CENTRAL)
	/* p_sec_params is NULL. */
	__cmock_ble_conn_state_role_ExpectAndReturn(m_arbitrary_conn_handle, BLE_GAP_ROLE_PERIPH);
	err = smd_link_secure(m_arbitrary_conn_handle, NULL, false);
	TEST_ASSERT_EQUAL_UINT32(NRF_ERROR_NULL, err);
#endif

	/* conn_handle is inactive. */
	__cmock_ble_conn_state_role_ExpectAndReturn(m_arbitrary_conn_handle, BLE_GAP_ROLE_INVALID);

	err = smd_link_secure(m_arbitrary_conn_handle, &m_arbitrary_sec_params, false);
	TEST_ASSERT_EQUAL_UINT32(BLE_ERROR_INVALID_CONN_HANDLE, err);


	/* conn_handle is inactive. */
	__cmock_ble_conn_state_role_ExpectAndReturn(m_arbitrary_conn_handle, BLE_GAP_ROLE_INVALID);

	err = smd_link_secure(m_arbitrary_conn_handle, &m_arbitrary_sec_params, false);
	TEST_ASSERT_EQUAL_UINT32(BLE_ERROR_INVALID_CONN_HANDLE, err);


	/* Peripheral role. */
	/* conn_handle became inactive at the last second. */
	__cmock_ble_conn_state_role_IgnoreAndReturn(BLE_GAP_ROLE_PERIPH);
	__cmock_sd_ble_gap_authenticate_ExpectAndReturn(
		m_arbitrary_conn_handle, NULL, BLE_ERROR_INVALID_CONN_HANDLE);
	__cmock_sd_ble_gap_authenticate_IgnoreArg_p_sec_params();

	err = smd_link_secure(m_arbitrary_conn_handle, &m_arbitrary_sec_params, false);

	TEST_ASSERT_EQUAL_UINT32(BLE_ERROR_INVALID_CONN_HANDLE, err);

	/* SMP Timeout */
	__cmock_sd_ble_gap_authenticate_ExpectAndReturn(
		m_arbitrary_conn_handle, NULL, NRF_ERROR_TIMEOUT);
	__cmock_sd_ble_gap_authenticate_IgnoreArg_p_sec_params();

	err = smd_link_secure(m_arbitrary_conn_handle, &m_arbitrary_sec_params, false);

	TEST_ASSERT_EQUAL_UINT32(NRF_ERROR_TIMEOUT, err);

	/* SoftDevice busy */
	__cmock_sd_ble_gap_authenticate_ExpectAndReturn(
		m_arbitrary_conn_handle, NULL, NRF_ERROR_BUSY);
	__cmock_sd_ble_gap_authenticate_IgnoreArg_p_sec_params();

	err = smd_link_secure(m_arbitrary_conn_handle, &m_arbitrary_sec_params, false);

	TEST_ASSERT_EQUAL_UINT32(NRF_ERROR_BUSY, err);

	/* SoftDevice invalid state */
	__cmock_sd_ble_gap_authenticate_ExpectAndReturn(
		m_arbitrary_conn_handle, NULL, NRF_ERROR_INVALID_STATE);
	__cmock_sd_ble_gap_authenticate_IgnoreArg_p_sec_params();

	err = smd_link_secure(m_arbitrary_conn_handle, &m_arbitrary_sec_params, false);

	TEST_ASSERT_EQUAL_UINT32(NRF_ERROR_INVALID_STATE, err);

	/* SoftDevice invalid params */
	__cmock_sd_ble_gap_authenticate_ExpectAndReturn(
		m_arbitrary_conn_handle, NULL, NRF_ERROR_INVALID_PARAM);
	__cmock_sd_ble_gap_authenticate_IgnoreArg_p_sec_params();

	err = smd_link_secure(m_arbitrary_conn_handle, &m_arbitrary_sec_params, false);

	TEST_ASSERT_EQUAL_UINT32(NRF_ERROR_INVALID_PARAM, err);

	/* SoftDevice no mem */
	__cmock_sd_ble_gap_authenticate_ExpectAndReturn(
		m_arbitrary_conn_handle, NULL, NRF_ERROR_NO_MEM);
	__cmock_sd_ble_gap_authenticate_IgnoreArg_p_sec_params();

	err = smd_link_secure(m_arbitrary_conn_handle, &m_arbitrary_sec_params, false);

	TEST_ASSERT_EQUAL_UINT32(NRF_ERROR_BUSY, err);

	/* Successfully called authenticate. */
	__cmock_sd_ble_gap_authenticate_ExpectWithArrayAndReturn(
		m_arbitrary_conn_handle, &m_arbitrary_sec_params, 1, NRF_SUCCESS);

	err = smd_link_secure(m_arbitrary_conn_handle, &m_arbitrary_sec_params, false);

	TEST_ASSERT_EQUAL_UINT32(NRF_SUCCESS, err);

#if defined(BLE_GAP_ROLE_CENTRAL)
	/* Central Role */
	__cmock_ble_conn_state_role_IgnoreAndReturn(BLE_GAP_ROLE_CENTRAL);

	/* NULL params => reject security request. */
	__cmock_sd_ble_gap_authenticate_ExpectAndReturn(m_arbitrary_conn_handle, NULL, NRF_SUCCESS);
	err = smd_link_secure(m_arbitrary_conn_handle, NULL, false);
	TEST_ASSERT_EQUAL_UINT32(NRF_SUCCESS, err);

	/* No stored data (invalid peer id). Error from .._authenticate(). */
	__cmock_ble_conn_state_user_flag_set_Expect(
		m_arbitrary_conn_handle, m_arbitrary_flag_id_allow, false);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(
		m_arbitrary_conn_handle, PM_PEER_ID_INVALID); /* HERE */
	__cmock_sd_ble_gap_authenticate_ExpectWithArrayAndReturn(
		m_arbitrary_conn_handle, &sec_params_bonding, 1, NRF_ERROR_BUSY);
	__cmock_ble_conn_state_user_flag_set_Expect(
		m_arbitrary_conn_handle, m_arbitrary_flag_id_sec_proc, false);

	err = smd_link_secure(m_arbitrary_conn_handle, &sec_params_bonding, false);

	TEST_ASSERT_EQUAL_UINT32(NRF_ERROR_BUSY, err);

	/* No stored data (invalid peer id). Error from .._authenticate(). */
	__cmock_ble_conn_state_user_flag_set_Expect(
		m_arbitrary_conn_handle, m_arbitrary_flag_id_allow, false);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(
		m_arbitrary_conn_handle, PM_PEER_ID_INVALID); /* HERE */
	__cmock_sd_ble_gap_authenticate_ExpectWithArrayAndReturn(
		m_arbitrary_conn_handle, &sec_params_bonding, 1, NRF_ERROR_INVALID_PARAM);
	__cmock_ble_conn_state_user_flag_set_Expect(
		m_arbitrary_conn_handle, m_arbitrary_flag_id_sec_proc, false);

	err = smd_link_secure(m_arbitrary_conn_handle, &sec_params_bonding, false);

	TEST_ASSERT_EQUAL_UINT32(NRF_ERROR_INVALID_PARAM, err);

	/* No stored data (invalid peer id). Error from .._authenticate().
	 * Converted to NRF_ERROR_BUSY.
	 */
	__cmock_ble_conn_state_user_flag_set_Expect(
		m_arbitrary_conn_handle, m_arbitrary_flag_id_allow, false);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(
		m_arbitrary_conn_handle, PM_PEER_ID_INVALID); /* HERE */
	__cmock_sd_ble_gap_authenticate_ExpectWithArrayAndReturn(
		m_arbitrary_conn_handle, &sec_params_bonding, 1, NRF_ERROR_NO_MEM);
	__cmock_ble_conn_state_user_flag_set_Expect(
		m_arbitrary_conn_handle, m_arbitrary_flag_id_sec_proc, false);

	err = smd_link_secure(m_arbitrary_conn_handle, &sec_params_bonding, false);

	TEST_ASSERT_EQUAL_UINT32(NRF_ERROR_BUSY, err);

	/* No stored data (invalid peer id).  .._authenticate() succeeds. */
	__cmock_ble_conn_state_user_flag_set_Expect(
		m_arbitrary_conn_handle, m_arbitrary_flag_id_allow, false);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(
		m_arbitrary_conn_handle, PM_PEER_ID_INVALID); /* HERE */
	__cmock_sd_ble_gap_authenticate_ExpectWithArrayAndReturn(
		m_arbitrary_conn_handle, &sec_params_bonding, 1, NRF_SUCCESS);
	sec_proc_expect_pairing(true, m_arbitrary_peer_id);

	err = smd_link_secure(m_arbitrary_conn_handle, &sec_params_bonding, false);

	TEST_ASSERT_EQUAL_UINT32(NRF_SUCCESS, err);
	TEST_ASSERT_EQUAL_UINT32(1 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	expect_sec_proc_start_evt(
		&m_evt_handler_records[0], PM_CONN_SEC_PROCEDURE_BONDING, m_arbitrary_peer_id);
	evt_handler_call_record_clear();

	/* No stored data (invalid peer id).
	 * .._authenticate() succeeds. Pairing only - no bonding.
	 */
	__cmock_ble_conn_state_user_flag_set_Expect(
		m_arbitrary_conn_handle, m_arbitrary_flag_id_allow, false);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(
		m_arbitrary_conn_handle, PM_PEER_ID_INVALID); /* HERE */
	__cmock_sd_ble_gap_authenticate_ExpectWithArrayAndReturn(
		m_arbitrary_conn_handle, &sec_params_pairing, 1, NRF_SUCCESS);
	sec_proc_expect_pairing(false, PM_PEER_ID_INVALID);

	err = smd_link_secure(m_arbitrary_conn_handle, &m_arbitrary_sec_params, false);

	TEST_ASSERT_EQUAL_UINT32(NRF_SUCCESS, err);
	TEST_ASSERT_EQUAL_UINT32(1 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	expect_sec_proc_start_evt(
		&m_evt_handler_records[0], PM_CONN_SEC_PROCEDURE_PAIRING, PM_PEER_ID_INVALID);
	evt_handler_call_record_clear();

	/* Invalid master ID. Error from .._authenticate(). */
	__cmock_ble_conn_state_user_flag_set_Expect(
		m_arbitrary_conn_handle, m_arbitrary_flag_id_allow, false);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(
		m_arbitrary_conn_handle, m_arbitrary_peer_id);
	__cmock_pdb_peer_data_ptr_get_ExpectAndReturn(
		m_arbitrary_peer_id, PM_PEER_DATA_ID_BONDING, NULL, NRF_SUCCESS);
	__cmock_pdb_peer_data_ptr_get_IgnoreArg_p_peer_data();
	__cmock_pdb_peer_data_ptr_get_ReturnThruPtr_p_peer_data(&returned_peer_data);
	__cmock_im_master_id_is_valid_ExpectAndReturn(
		&bonding_data.peer_ltk.master_id, false); /* HERE */
	__cmock_ble_conn_state_user_flag_set_Expect(
		m_arbitrary_conn_handle, m_arbitrary_flag_id_sec_proc, false);

	err = smd_link_secure(m_arbitrary_conn_handle, &sec_params_bonding, false);

	TEST_ASSERT_EQUAL_UINT32(NRF_ERROR_INVALID_DATA, err);

	/* No key. */
	sec_params_bonding.mitm = true;

	__cmock_ble_conn_state_user_flag_set_Expect(
		m_arbitrary_conn_handle, m_arbitrary_flag_id_allow, false);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(
		m_arbitrary_conn_handle, m_arbitrary_peer_id);
	__cmock_pdb_peer_data_ptr_get_ExpectAndReturn(
		m_arbitrary_peer_id, PM_PEER_DATA_ID_BONDING, NULL, NRF_ERROR_NOT_FOUND); /* HERE */
	__cmock_pdb_peer_data_ptr_get_IgnoreArg_p_peer_data();
	__cmock_ble_conn_state_user_flag_set_Expect(
		m_arbitrary_conn_handle, m_arbitrary_flag_id_sec_proc, false);

	err = smd_link_secure(m_arbitrary_conn_handle, &sec_params_bonding, false);

	TEST_ASSERT_EQUAL_UINT32(NRF_ERROR_BUSY, err);
	TEST_ASSERT_EQUAL_UINT32(0 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	evt_handler_call_record_clear();

	/* Force repairing. */
	__cmock_ble_conn_state_user_flag_set_Expect(
		m_arbitrary_conn_handle, m_arbitrary_flag_id_allow, true);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(
		m_arbitrary_conn_handle, m_arbitrary_peer_id);
	__cmock_sd_ble_gap_authenticate_ExpectWithArrayAndReturn(
		m_arbitrary_conn_handle, &sec_params_bonding, 1, NRF_SUCCESS);
	sec_proc_expect_pairing(true, m_arbitrary_peer_id);

	err = smd_link_secure(m_arbitrary_conn_handle, &sec_params_bonding, true);

	TEST_ASSERT_EQUAL_UINT32(NRF_SUCCESS, err);
	TEST_ASSERT_EQUAL_UINT32(1 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	expect_sec_proc_start_evt(
		&m_evt_handler_records[0], PM_CONN_SEC_PROCEDURE_BONDING, m_arbitrary_peer_id);
	evt_handler_call_record_clear();

	bonding_data.peer_ltk.enc_info.auth = true;

	/* Error from .._read_buf_get() */
	__cmock_ble_conn_state_user_flag_set_Expect(
		m_arbitrary_conn_handle, m_arbitrary_flag_id_allow, false);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(
		m_arbitrary_conn_handle, m_arbitrary_peer_id);
	__cmock_pdb_peer_data_ptr_get_ExpectAndReturn(
		m_arbitrary_peer_id, PM_PEER_DATA_ID_BONDING, NULL, NRF_ERROR_BUSY);
	__cmock_pdb_peer_data_ptr_get_IgnoreArg_p_peer_data();
	__cmock_pdb_peer_data_ptr_get_ReturnThruPtr_p_peer_data(&returned_peer_data);
	__cmock_ble_conn_state_user_flag_set_Expect(
		m_arbitrary_conn_handle, m_arbitrary_flag_id_sec_proc, false);

	err = smd_link_secure(m_arbitrary_conn_handle, &sec_params_bonding, false);

	TEST_ASSERT_EQUAL_UINT32(NRF_ERROR_BUSY, err);

	/* Error from .._encrypt() */
	__cmock_ble_conn_state_user_flag_set_Expect(
		m_arbitrary_conn_handle, m_arbitrary_flag_id_allow, false);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(
		m_arbitrary_conn_handle, m_arbitrary_peer_id);
	__cmock_pdb_peer_data_ptr_get_ExpectAndReturn(
		m_arbitrary_peer_id, PM_PEER_DATA_ID_BONDING, NULL, NRF_SUCCESS);
	__cmock_pdb_peer_data_ptr_get_IgnoreArg_p_peer_data();
	__cmock_pdb_peer_data_ptr_get_ReturnThruPtr_p_peer_data(&returned_peer_data);
	__cmock_im_master_id_is_valid_ExpectAndReturn(&bonding_data.peer_ltk.master_id, true);
	__cmock_sd_ble_gap_encrypt_ExpectAndReturn(
		m_arbitrary_conn_handle, &bonding_data.peer_ltk.master_id,
		&bonding_data.peer_ltk.enc_info, BLE_ERROR_INVALID_CONN_HANDLE);  /* HERE */
	__cmock_ble_conn_state_user_flag_set_Expect(
		m_arbitrary_conn_handle, m_arbitrary_flag_id_sec_proc, false);

	err = smd_link_secure(m_arbitrary_conn_handle, &sec_params_bonding, false);

	TEST_ASSERT_EQUAL_UINT32(BLE_ERROR_INVALID_CONN_HANDLE, err);

	/* .._encrypt() succceeds. */
	__cmock_ble_conn_state_user_flag_set_Expect(
		m_arbitrary_conn_handle, m_arbitrary_flag_id_allow, false);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(
		m_arbitrary_conn_handle, m_arbitrary_peer_id);
	__cmock_pdb_peer_data_ptr_get_ExpectAndReturn(
		m_arbitrary_peer_id, PM_PEER_DATA_ID_BONDING, NULL, NRF_SUCCESS);
	__cmock_pdb_peer_data_ptr_get_IgnoreArg_p_peer_data();
	__cmock_pdb_peer_data_ptr_get_ReturnThruPtr_p_peer_data(&returned_peer_data);
	__cmock_im_master_id_is_valid_ExpectAndReturn(&bonding_data.peer_ltk.master_id, true);
	__cmock_sd_ble_gap_encrypt_ExpectAndReturn(
		m_arbitrary_conn_handle, &bonding_data.peer_ltk.master_id,
		&bonding_data.peer_ltk.enc_info, NRF_SUCCESS);  /* HERE */
	sec_proc_expect_enc();

	err = smd_link_secure(m_arbitrary_conn_handle, &sec_params_bonding, false);

	TEST_ASSERT_EQUAL_UINT32(NRF_SUCCESS, err);
	TEST_ASSERT_EQUAL_UINT32(1 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	expect_sec_proc_start_evt(
		&m_evt_handler_records[0], PM_CONN_SEC_PROCEDURE_ENCRYPTION, m_arbitrary_peer_id);
	evt_handler_call_record_clear();

	/* .._encrypt() succceeds - LESC. */
	sec_params_bonding.lesc = true;
	bonding_data.own_ltk.enc_info.lesc = true;
	bonding_data.own_ltk.enc_info.auth = true;

	__cmock_ble_conn_state_user_flag_set_Expect(
		m_arbitrary_conn_handle, m_arbitrary_flag_id_allow, false);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(
		m_arbitrary_conn_handle, m_arbitrary_peer_id);
	__cmock_pdb_peer_data_ptr_get_ExpectAndReturn(
		m_arbitrary_peer_id, PM_PEER_DATA_ID_BONDING, NULL, NRF_SUCCESS);
	__cmock_pdb_peer_data_ptr_get_IgnoreArg_p_peer_data();
	__cmock_pdb_peer_data_ptr_get_ReturnThruPtr_p_peer_data(&returned_peer_data);
	__cmock_sd_ble_gap_encrypt_ExpectAndReturn(
		m_arbitrary_conn_handle, &bonding_data.own_ltk.master_id,
		&bonding_data.own_ltk.enc_info, NRF_SUCCESS);  /* HERE */
	sec_proc_expect_enc();

	err = smd_link_secure(m_arbitrary_conn_handle, &sec_params_bonding, false);

	TEST_ASSERT_EQUAL_UINT32(NRF_SUCCESS, err);
	TEST_ASSERT_EQUAL_UINT32(1 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	expect_sec_proc_start_evt(
		&m_evt_handler_records[0], PM_CONN_SEC_PROCEDURE_ENCRYPTION, m_arbitrary_peer_id);
	evt_handler_call_record_clear();
#endif
}


void ble_evt_init(ble_evt_t *p_ble_evt, uint8_t evt_id, uint16_t conn_handle)
{
	memset(p_ble_evt, 0, sizeof(ble_evt_t));
	p_ble_evt->header.evt_id            = evt_id;
	p_ble_evt->evt.gap_evt.conn_handle  = conn_handle;
	p_ble_evt->header.evt_len           = sizeof(ble_gap_evt_t);
}


void sec_params_req_evt_constuct(ble_evt_t *p_ble_evt, uint16_t conn_handle, bool bond)
{
	ble_evt_init(p_ble_evt, BLE_GAP_EVT_SEC_PARAMS_REQUEST, conn_handle);
	p_ble_evt->evt.gap_evt.params.sec_params_request.peer_params.bond = bond;
}

void sec_info_req_evt_constuct(ble_evt_t         *p_ble_evt,
				   uint16_t            conn_handle,
				   ble_gap_master_id_t master_id,
				   uint8_t             enc_info,
				   uint8_t             id_info)
{
	ble_evt_init(p_ble_evt, BLE_GAP_EVT_SEC_INFO_REQUEST, conn_handle);
	p_ble_evt->evt.gap_evt.params.sec_info_request.master_id = master_id;
	p_ble_evt->evt.gap_evt.params.sec_info_request.enc_info  = enc_info;
	p_ble_evt->evt.gap_evt.params.sec_info_request.id_info   = id_info;
}

void sec_request_evt_constuct(ble_evt_t *p_ble_evt,
				  uint16_t    conn_handle,
				  uint8_t     bond,
				  uint8_t     mitm)
{
#if defined(BLE_GAP_ROLE_CENTRAL)
	ble_evt_init(p_ble_evt, BLE_GAP_EVT_SEC_REQUEST, conn_handle);
	p_ble_evt->evt.gap_evt.params.sec_request.bond = bond;
	p_ble_evt->evt.gap_evt.params.sec_request.mitm = mitm;
#endif
}

void auth_status_evt_constuct(ble_evt_t         *p_ble_evt,
				  uint16_t            conn_handle,
				  uint8_t             auth_status,
				  uint8_t             bonded,
				  ble_gap_sec_kdist_t kdist_own,
				  ble_gap_sec_kdist_t kdist_peer)
{
	ble_evt_init(p_ble_evt, BLE_GAP_EVT_AUTH_STATUS, conn_handle);
	p_ble_evt->evt.gap_evt.params.auth_status.auth_status = auth_status;
	p_ble_evt->evt.gap_evt.params.auth_status.bonded = bonded;
	p_ble_evt->evt.gap_evt.params.auth_status.sm1_levels.lv3 += 1;
	p_ble_evt->evt.gap_evt.params.auth_status.kdist_own = kdist_own;
	p_ble_evt->evt.gap_evt.params.auth_status.kdist_peer = kdist_peer;
	p_ble_evt->evt.gap_evt.params.auth_status.error_src = BLE_GAP_SEC_STATUS_SOURCE_REMOTE;
}


void conn_sec_update_evt_constuct(ble_evt_t *p_ble_evt, uint16_t conn_handle, uint8_t level)
{
	ble_evt_init(p_ble_evt, BLE_GAP_EVT_CONN_SEC_UPDATE, conn_handle);
	p_ble_evt->evt.gap_evt.params.conn_sec_update.conn_sec.sec_mode.lv = level;
}


void disconnected_evt_constuct(ble_evt_t *p_ble_evt, uint16_t conn_handle, uint8_t reason)
{
	ble_evt_init(p_ble_evt, BLE_GAP_EVT_DISCONNECTED, conn_handle);
	p_ble_evt->evt.gap_evt.params.disconnected.reason = reason;
}


void timeout_evt_constuct(ble_evt_t *p_ble_evt, uint16_t conn_handle, uint8_t src)
{
	ble_evt_init(p_ble_evt, BLE_GAP_EVT_TIMEOUT, conn_handle);
	p_ble_evt->evt.gap_evt.params.timeout.src = src;
}


ble_evt_t *sec_params_req_evt(uint16_t conn_handle, bool bond)
{
	static ble_evt_t ble_evt;

	sec_params_req_evt_constuct(&ble_evt, conn_handle, bond);
	return &ble_evt;
}


ble_evt_t *sec_info_req_evt(uint16_t            conn_handle,
				 ble_gap_master_id_t master_id,
				 uint8_t             enc_info,
				 uint8_t             id_info)
{
	static ble_evt_t ble_evt;

	sec_info_req_evt_constuct(&ble_evt, conn_handle, master_id, enc_info, id_info);
	return &ble_evt;
}

ble_evt_t *sec_request_evt(uint16_t conn_handle,
			uint8_t  bond,
			uint8_t  mitm)
{
	static ble_evt_t ble_evt;

	sec_request_evt_constuct(&ble_evt, conn_handle, bond, mitm);
	return &ble_evt;
}


ble_evt_t *auth_status_evt(uint16_t            conn_handle,
				uint8_t             auth_status,
				uint8_t             bonded,
				ble_gap_sec_kdist_t kdist_own,
				ble_gap_sec_kdist_t kdist_peer)
{
	static ble_evt_t ble_evt;

	auth_status_evt_constuct(&ble_evt, conn_handle, auth_status, bonded, kdist_own, kdist_peer);
	return &ble_evt;
}


ble_evt_t *conn_sec_update_evt(uint16_t conn_handle, uint8_t level)
{
	static ble_evt_t ble_evt;

	conn_sec_update_evt_constuct(&ble_evt, conn_handle, level);
	return &ble_evt;
}


ble_evt_t *disconnected_evt(uint16_t conn_handle, uint8_t reason)
{
	static ble_evt_t ble_evt;

	disconnected_evt_constuct(&ble_evt, conn_handle, reason);
	return &ble_evt;
}


ble_evt_t *timeout_evt(uint16_t conn_handle, uint8_t src)
{
	static ble_evt_t ble_evt;

	timeout_evt_constuct(&ble_evt, conn_handle, src);
	return &ble_evt;
}


void test_smd_ble_evt_handler(void)
{
	pm_peer_data_flash_t returned_peer_data;

	memset(&returned_peer_data, 0, sizeof(pm_peer_data_flash_t));
	returned_peer_data.data_id        = PM_PEER_DATA_ID_BONDING;
	returned_peer_data.p_bonding_data = &m_arbitrary_bonding_data;

	/* Sec params request. Peripheral. Bonding. */
	__cmock_ble_conn_state_role_ExpectAndReturn(m_arbitrary_conn_handle, BLE_GAP_ROLE_PERIPH);
	__cmock_ble_conn_state_user_flag_set_Expect(
		m_arbitrary_conn_handle, m_arbitrary_flag_id_sec_proc, true);
	__cmock_ble_conn_state_user_flag_set_Expect(
		m_arbitrary_conn_handle, m_arbitrary_flag_id_pairing,  true);
	__cmock_ble_conn_state_user_flag_set_Expect(
		m_arbitrary_conn_handle, m_arbitrary_flag_id_bonding,  true);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(
		m_arbitrary_conn_handle, m_arbitrary_peer_id);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(
		m_arbitrary_conn_handle, m_arbitrary_peer_id);

	smd_ble_evt_handler(sec_params_req_evt(m_arbitrary_conn_handle, true));

	TEST_ASSERT_EQUAL_UINT32(2 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	expect_sec_proc_start_evt(
		&m_evt_handler_records[0], PM_CONN_SEC_PROCEDURE_BONDING, m_arbitrary_peer_id);
	TEST_ASSERT_EQUAL_UINT32(
		m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].conn_handle,
		m_arbitrary_conn_handle);
	TEST_ASSERT_EQUAL_UINT32(
		m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].evt_id,
		PM_EVT_CONN_SEC_PARAMS_REQ);
	evt_handler_call_record_clear();

#if defined(BLE_GAP_ROLE_CENTRAL)
	/* Sec params request. Central. Bonding. */
	__cmock_ble_conn_state_role_ExpectAndReturn(m_arbitrary_conn_handle, BLE_GAP_ROLE_CENTRAL);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(
		m_arbitrary_conn_handle, m_arbitrary_peer_id);

	smd_ble_evt_handler(sec_params_req_evt(m_arbitrary_conn_handle, true));

	TEST_ASSERT_EQUAL_UINT32(1 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	TEST_ASSERT_EQUAL_UINT32(
		m_evt_handler_records[0 * SMD_EVENT_HANDLERS_CNT].conn_handle,
		m_arbitrary_conn_handle);
	TEST_ASSERT_EQUAL_UINT32(
		m_evt_handler_records[0 * SMD_EVENT_HANDLERS_CNT].evt_id,
		PM_EVT_CONN_SEC_PARAMS_REQ);
	TEST_ASSERT_EQUAL_UINT32(
		m_arbitrary_peer_id,
		m_evt_handler_records[0 * SMD_EVENT_HANDLERS_CNT].peer_id);
	evt_handler_call_record_clear();
#endif

	/* Sec info request error. */
	ble_evt_t *p_ble_evt = sec_info_req_evt(m_arbitrary_conn_handle,
						m_arbitrary_master_id, 1, 0);

	__cmock_im_peer_id_get_by_master_id_ExpectAndReturn(
		&p_ble_evt->evt.gap_evt.params.sec_info_request.master_id, m_arbitrary_peer_id);
	__cmock_im_new_peer_id_Expect(m_arbitrary_conn_handle, m_arbitrary_peer_id);
	__cmock_ble_conn_state_user_flag_set_Expect(
		m_arbitrary_conn_handle, m_arbitrary_flag_id_sec_proc, true);
	__cmock_ble_conn_state_user_flag_set_Expect(
		m_arbitrary_conn_handle, m_arbitrary_flag_id_pairing, false);
	__cmock_ble_conn_state_user_flag_set_Expect(
		m_arbitrary_conn_handle, m_arbitrary_flag_id_bonding, false);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(
		m_arbitrary_conn_handle, m_arbitrary_peer_id);
	__cmock_pdb_peer_data_ptr_get_ExpectAndReturn(
		m_arbitrary_peer_id, PM_PEER_DATA_ID_BONDING, NULL, NRF_ERROR_NOT_FOUND);
	__cmock_pdb_peer_data_ptr_get_IgnoreArg_p_peer_data();
	__cmock_sd_ble_gap_sec_info_reply_ExpectAndReturn(
		m_arbitrary_conn_handle, NULL, NULL, NULL, NRF_ERROR_INVALID_PARAM);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(
		m_arbitrary_conn_handle, m_arbitrary_peer_id);

	smd_ble_evt_handler(p_ble_evt);

	TEST_ASSERT_EQUAL_UINT32(2 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	expect_sec_proc_start_evt(
		&m_evt_handler_records[0], PM_CONN_SEC_PROCEDURE_ENCRYPTION, m_arbitrary_peer_id);
	TEST_ASSERT_EQUAL_UINT32(
		PM_EVT_ERROR_UNEXPECTED, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].evt_id);
	TEST_ASSERT_EQUAL_UINT32(
		m_arbitrary_conn_handle,
		m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].conn_handle);
	TEST_ASSERT_EQUAL_UINT32(
		NRF_ERROR_INVALID_PARAM,
		m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].params.error_unexpected.error);
	TEST_ASSERT_EQUAL_UINT32(
		m_arbitrary_peer_id,
		m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].peer_id);
	evt_handler_call_record_clear();

	/* Sec info request error (INVALID_STATE). */
	p_ble_evt = sec_info_req_evt(m_arbitrary_conn_handle, m_arbitrary_master_id, 1, 0);

	__cmock_im_peer_id_get_by_master_id_ExpectAndReturn(
		&p_ble_evt->evt.gap_evt.params.sec_info_request.master_id, m_arbitrary_peer_id);
	__cmock_im_new_peer_id_Expect(m_arbitrary_conn_handle, m_arbitrary_peer_id);
	__cmock_ble_conn_state_user_flag_set_Expect(
		m_arbitrary_conn_handle, m_arbitrary_flag_id_sec_proc, true);
	__cmock_ble_conn_state_user_flag_set_Expect(
		m_arbitrary_conn_handle, m_arbitrary_flag_id_pairing, false);
	__cmock_ble_conn_state_user_flag_set_Expect(
		m_arbitrary_conn_handle, m_arbitrary_flag_id_bonding, false);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(
		m_arbitrary_conn_handle, m_arbitrary_peer_id);
	__cmock_pdb_peer_data_ptr_get_ExpectAndReturn(
		m_arbitrary_peer_id, PM_PEER_DATA_ID_BONDING, NULL, NRF_ERROR_NOT_FOUND);
	__cmock_pdb_peer_data_ptr_get_IgnoreArg_p_peer_data();
	__cmock_sd_ble_gap_sec_info_reply_ExpectAndReturn(
		m_arbitrary_conn_handle, NULL, NULL, NULL, NRF_ERROR_INVALID_STATE);

	smd_ble_evt_handler(p_ble_evt);

	TEST_ASSERT_EQUAL_UINT32(1 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	expect_sec_proc_start_evt(
		&m_evt_handler_records[0], PM_CONN_SEC_PROCEDURE_ENCRYPTION, m_arbitrary_peer_id);
	evt_handler_call_record_clear();

	/* Sec info request no available key. */
	p_ble_evt = sec_info_req_evt(m_arbitrary_conn_handle, m_arbitrary_master_id, 1, 0);

	__cmock_im_peer_id_get_by_master_id_ExpectAndReturn(
		&p_ble_evt->evt.gap_evt.params.sec_info_request.master_id, m_arbitrary_peer_id);
	__cmock_im_new_peer_id_Expect(m_arbitrary_conn_handle, m_arbitrary_peer_id);
	__cmock_ble_conn_state_user_flag_set_Expect(
		m_arbitrary_conn_handle, m_arbitrary_flag_id_sec_proc, true);
	__cmock_ble_conn_state_user_flag_set_Expect(
		m_arbitrary_conn_handle, m_arbitrary_flag_id_pairing, false);
	__cmock_ble_conn_state_user_flag_set_Expect(
		m_arbitrary_conn_handle, m_arbitrary_flag_id_bonding, false);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(
		m_arbitrary_conn_handle, m_arbitrary_peer_id);
	__cmock_pdb_peer_data_ptr_get_ExpectAndReturn(
		m_arbitrary_peer_id, PM_PEER_DATA_ID_BONDING, NULL, NRF_ERROR_NOT_FOUND);
	__cmock_pdb_peer_data_ptr_get_IgnoreArg_p_peer_data();
	__cmock_sd_ble_gap_sec_info_reply_ExpectAndReturn(
		m_arbitrary_conn_handle, NULL, NULL, NULL, NRF_SUCCESS);
	sec_proc_expect_fail(m_arbitrary_peer_id);

	smd_ble_evt_handler(p_ble_evt);

	TEST_ASSERT_EQUAL_UINT32(2 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	expect_sec_proc_start_evt(
		&m_evt_handler_records[0], PM_CONN_SEC_PROCEDURE_ENCRYPTION, m_arbitrary_peer_id);
	TEST_ASSERT_EQUAL_UINT32(
		PM_EVT_CONN_SEC_FAILED, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].evt_id);
	TEST_ASSERT_EQUAL_UINT32(
		m_arbitrary_conn_handle,
		m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].conn_handle);
	TEST_ASSERT_EQUAL_UINT32(
		PM_CONN_SEC_ERROR_PIN_OR_KEY_MISSING,
		m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].params.conn_sec_failed.error);
	TEST_ASSERT_EQUAL_UINT32(
		BLE_GAP_SEC_STATUS_SOURCE_LOCAL,
		m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].params.conn_sec_failed.error_src);
	TEST_ASSERT_EQUAL_UINT32(
		m_arbitrary_peer_id, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].peer_id);
	evt_handler_call_record_clear();

	/* Sec info request invalid master id. */
	p_ble_evt = sec_info_req_evt(m_arbitrary_conn_handle, m_arbitrary_master_id, 1, 0);
	m_arbitrary_bonding_data.own_role = BLE_GAP_ROLE_PERIPH;

	__cmock_im_peer_id_get_by_master_id_ExpectAndReturn(
		&p_ble_evt->evt.gap_evt.params.sec_info_request.master_id, m_arbitrary_peer_id);
	__cmock_im_new_peer_id_Expect(m_arbitrary_conn_handle, m_arbitrary_peer_id);
	__cmock_ble_conn_state_user_flag_set_Expect(
		m_arbitrary_conn_handle, m_arbitrary_flag_id_sec_proc, true);
	__cmock_ble_conn_state_user_flag_set_Expect(
		m_arbitrary_conn_handle, m_arbitrary_flag_id_pairing,  false);
	__cmock_ble_conn_state_user_flag_set_Expect(
		m_arbitrary_conn_handle, m_arbitrary_flag_id_bonding,  false);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(
		m_arbitrary_conn_handle, m_arbitrary_peer_id);
	__cmock_pdb_peer_data_ptr_get_ExpectAndReturn(
		m_arbitrary_peer_id, PM_PEER_DATA_ID_BONDING, NULL, NRF_SUCCESS);
	__cmock_pdb_peer_data_ptr_get_IgnoreArg_p_peer_data();
	__cmock_pdb_peer_data_ptr_get_ReturnThruPtr_p_peer_data(&returned_peer_data);
	__cmock_im_master_ids_compare_ExpectAndReturn(&returned_peer_data.p_bonding_data->own_ltk.master_id, &p_ble_evt->evt.gap_evt.params.sec_info_request.master_id, false);
	__cmock_sd_ble_gap_sec_info_reply_ExpectAndReturn(m_arbitrary_conn_handle, NULL, NULL, NULL, NRF_SUCCESS);
	sec_proc_expect_fail(m_arbitrary_peer_id);

	smd_ble_evt_handler(p_ble_evt);

	TEST_ASSERT_EQUAL_UINT32(2 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	expect_sec_proc_start_evt(&m_evt_handler_records[0], PM_CONN_SEC_PROCEDURE_ENCRYPTION, m_arbitrary_peer_id);
	TEST_ASSERT_EQUAL_UINT32(PM_EVT_CONN_SEC_FAILED, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].evt_id);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_conn_handle, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].conn_handle);
	TEST_ASSERT_EQUAL_UINT32(PM_CONN_SEC_ERROR_PIN_OR_KEY_MISSING, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].params.conn_sec_failed.error);
	TEST_ASSERT_EQUAL_UINT32(BLE_GAP_SEC_STATUS_SOURCE_LOCAL, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].params.conn_sec_failed.error_src);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_peer_id, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].peer_id);
	evt_handler_call_record_clear();

	/* Sec info wrong master id. */
	p_ble_evt = sec_info_req_evt(m_arbitrary_conn_handle, m_arbitrary_master_id, 1, 0);

	__cmock_im_peer_id_get_by_master_id_ExpectAndReturn(&p_ble_evt->evt.gap_evt.params.sec_info_request.master_id, m_arbitrary_peer_id);
	__cmock_im_new_peer_id_Expect(m_arbitrary_conn_handle, m_arbitrary_peer_id);
	__cmock_ble_conn_state_user_flag_set_Expect(m_arbitrary_conn_handle, m_arbitrary_flag_id_sec_proc, true);
	__cmock_ble_conn_state_user_flag_set_Expect(m_arbitrary_conn_handle, m_arbitrary_flag_id_pairing,  false);
	__cmock_ble_conn_state_user_flag_set_Expect(m_arbitrary_conn_handle, m_arbitrary_flag_id_bonding,  false);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_peer_id);
	__cmock_pdb_peer_data_ptr_get_ExpectAndReturn(m_arbitrary_peer_id, PM_PEER_DATA_ID_BONDING, NULL, NRF_SUCCESS);
	__cmock_pdb_peer_data_ptr_get_IgnoreArg_p_peer_data();
	__cmock_pdb_peer_data_ptr_get_ReturnThruPtr_p_peer_data(&returned_peer_data);
	__cmock_im_master_ids_compare_ExpectAndReturn(&returned_peer_data.p_bonding_data->own_ltk.master_id, &p_ble_evt->evt.gap_evt.params.sec_info_request.master_id, false);
	__cmock_sd_ble_gap_sec_info_reply_ExpectAndReturn(m_arbitrary_conn_handle, NULL, NULL, NULL, NRF_SUCCESS);
	sec_proc_expect_fail(m_arbitrary_peer_id);

	smd_ble_evt_handler(p_ble_evt);

	TEST_ASSERT_EQUAL_UINT32(2 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	expect_sec_proc_start_evt(&m_evt_handler_records[0], PM_CONN_SEC_PROCEDURE_ENCRYPTION, m_arbitrary_peer_id);
	TEST_ASSERT_EQUAL_UINT32(PM_EVT_CONN_SEC_FAILED, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].evt_id);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_conn_handle, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].conn_handle);
	TEST_ASSERT_EQUAL_UINT32(PM_CONN_SEC_ERROR_PIN_OR_KEY_MISSING, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].params.conn_sec_failed.error);
	TEST_ASSERT_EQUAL_UINT32(BLE_GAP_SEC_STATUS_SOURCE_LOCAL, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].params.conn_sec_failed.error_src);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_peer_id, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].peer_id);
	evt_handler_call_record_clear();

	/* Sec info request success - without enc_info. */
	p_ble_evt = sec_info_req_evt(m_arbitrary_conn_handle, m_arbitrary_master_id, 0, 0);

	__cmock_im_peer_id_get_by_master_id_ExpectAndReturn(&p_ble_evt->evt.gap_evt.params.sec_info_request.master_id, m_arbitrary_peer_id);
	__cmock_im_new_peer_id_Expect(m_arbitrary_conn_handle, m_arbitrary_peer_id);
	__cmock_ble_conn_state_user_flag_set_Expect(m_arbitrary_conn_handle, m_arbitrary_flag_id_sec_proc, true);
	__cmock_ble_conn_state_user_flag_set_Expect(m_arbitrary_conn_handle, m_arbitrary_flag_id_pairing,  false);
	__cmock_ble_conn_state_user_flag_set_Expect(m_arbitrary_conn_handle, m_arbitrary_flag_id_bonding,  false);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_peer_id);
	__cmock_pdb_peer_data_ptr_get_ExpectAndReturn(m_arbitrary_peer_id, PM_PEER_DATA_ID_BONDING, NULL, NRF_SUCCESS);
	__cmock_pdb_peer_data_ptr_get_IgnoreArg_p_peer_data();
	__cmock_pdb_peer_data_ptr_get_ReturnThruPtr_p_peer_data(&returned_peer_data);
	__cmock_sd_ble_gap_sec_info_reply_ExpectAndReturn(m_arbitrary_conn_handle, NULL, NULL, NULL, NRF_SUCCESS);

	smd_ble_evt_handler(p_ble_evt);

	TEST_ASSERT_EQUAL_UINT32(1 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	expect_sec_proc_start_evt(&m_evt_handler_records[0], PM_CONN_SEC_PROCEDURE_ENCRYPTION, m_arbitrary_peer_id);
	evt_handler_call_record_clear();

	/* Sec info request success. */
	p_ble_evt = sec_info_req_evt(m_arbitrary_conn_handle, m_arbitrary_master_id, 1, 0);

	__cmock_im_peer_id_get_by_master_id_ExpectAndReturn(&p_ble_evt->evt.gap_evt.params.sec_info_request.master_id, m_arbitrary_peer_id);
	__cmock_im_new_peer_id_Expect(m_arbitrary_conn_handle, m_arbitrary_peer_id);
	__cmock_ble_conn_state_user_flag_set_Expect(m_arbitrary_conn_handle, m_arbitrary_flag_id_sec_proc, true);
	__cmock_ble_conn_state_user_flag_set_Expect(m_arbitrary_conn_handle, m_arbitrary_flag_id_pairing,  false);
	__cmock_ble_conn_state_user_flag_set_Expect(m_arbitrary_conn_handle, m_arbitrary_flag_id_bonding,  false);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_peer_id);
	__cmock_pdb_peer_data_ptr_get_ExpectAndReturn(m_arbitrary_peer_id, PM_PEER_DATA_ID_BONDING, NULL, NRF_SUCCESS);
	__cmock_pdb_peer_data_ptr_get_IgnoreArg_p_peer_data();
	__cmock_pdb_peer_data_ptr_get_ReturnThruPtr_p_peer_data(&returned_peer_data);
	__cmock_im_master_ids_compare_ExpectAndReturn(&returned_peer_data.p_bonding_data->own_ltk.master_id, &p_ble_evt->evt.gap_evt.params.sec_info_request.master_id, true);
	__cmock_sd_ble_gap_sec_info_reply_ExpectAndReturn(m_arbitrary_conn_handle, &m_arbitrary_bonding_data.own_ltk.enc_info, NULL, NULL, NRF_SUCCESS);

	smd_ble_evt_handler(p_ble_evt);

	TEST_ASSERT_EQUAL_UINT32(1 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	expect_sec_proc_start_evt(&m_evt_handler_records[0], PM_CONN_SEC_PROCEDURE_ENCRYPTION, m_arbitrary_peer_id);
	evt_handler_call_record_clear();

	/* Sec info request failure, no master ID. */
	p_ble_evt = sec_info_req_evt(m_arbitrary_conn_handle, m_arbitrary_master_id, 1, 0);

	__cmock_im_peer_id_get_by_master_id_ExpectAndReturn(&p_ble_evt->evt.gap_evt.params.sec_info_request.master_id, PM_PEER_ID_INVALID);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, PM_PEER_ID_INVALID);
	__cmock_ble_conn_state_user_flag_set_Expect(m_arbitrary_conn_handle, m_arbitrary_flag_id_sec_proc, true);
	__cmock_ble_conn_state_user_flag_set_Expect(m_arbitrary_conn_handle, m_arbitrary_flag_id_pairing,  false);
	__cmock_ble_conn_state_user_flag_set_Expect(m_arbitrary_conn_handle, m_arbitrary_flag_id_bonding,  false);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, PM_PEER_ID_INVALID);
	__cmock_sd_ble_gap_sec_info_reply_ExpectAndReturn(m_arbitrary_conn_handle, NULL, NULL, NULL, NRF_SUCCESS);
	sec_proc_expect_fail(PM_PEER_ID_INVALID);

	smd_ble_evt_handler(p_ble_evt);

	TEST_ASSERT_EQUAL_UINT32(2 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	expect_sec_proc_start_evt(&m_evt_handler_records[0], PM_CONN_SEC_PROCEDURE_ENCRYPTION, PM_PEER_ID_INVALID);
	TEST_ASSERT_EQUAL_UINT32(PM_EVT_CONN_SEC_FAILED, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].evt_id);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_conn_handle, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].conn_handle);
	TEST_ASSERT_EQUAL_UINT32(PM_CONN_SEC_ERROR_PIN_OR_KEY_MISSING, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].params.conn_sec_failed.error);
	TEST_ASSERT_EQUAL_UINT32(BLE_GAP_SEC_STATUS_SOURCE_LOCAL, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].params.conn_sec_failed.error_src);
	TEST_ASSERT_EQUAL_UINT32(PM_PEER_ID_INVALID, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].peer_id);
	evt_handler_call_record_clear();

	/* Sec info request success - LESC. */
	p_ble_evt = sec_info_req_evt(m_arbitrary_conn_handle, m_arbitrary_master_id, 1, 0);
	m_arbitrary_bonding_data.own_ltk.enc_info.lesc = 1;

	__cmock_im_peer_id_get_by_master_id_ExpectAndReturn(&p_ble_evt->evt.gap_evt.params.sec_info_request.master_id, PM_PEER_ID_INVALID);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_peer_id);
	__cmock_ble_conn_state_user_flag_set_Expect(m_arbitrary_conn_handle, m_arbitrary_flag_id_sec_proc, true);
	__cmock_ble_conn_state_user_flag_set_Expect(m_arbitrary_conn_handle, m_arbitrary_flag_id_pairing,  false);
	__cmock_ble_conn_state_user_flag_set_Expect(m_arbitrary_conn_handle, m_arbitrary_flag_id_bonding,  false);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_peer_id);
	__cmock_pdb_peer_data_ptr_get_ExpectAndReturn(m_arbitrary_peer_id, PM_PEER_DATA_ID_BONDING, NULL, NRF_SUCCESS);
	__cmock_pdb_peer_data_ptr_get_IgnoreArg_p_peer_data();
	__cmock_pdb_peer_data_ptr_get_ReturnThruPtr_p_peer_data(&returned_peer_data);
	__cmock_sd_ble_gap_sec_info_reply_ExpectAndReturn(m_arbitrary_conn_handle, &m_arbitrary_bonding_data.own_ltk.enc_info, NULL, NULL, NRF_SUCCESS);

	smd_ble_evt_handler(p_ble_evt);

	TEST_ASSERT_EQUAL_UINT32(1 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	expect_sec_proc_start_evt(&m_evt_handler_records[0], PM_CONN_SEC_PROCEDURE_ENCRYPTION, m_arbitrary_peer_id);
	evt_handler_call_record_clear();

	m_arbitrary_bonding_data.own_ltk.enc_info.lesc = 0;


	/* Auth Status */
	/* Success - pairing only */
	ble_evt_t         *p_auth_status_evt;
	ble_gap_sec_kdist_t kdist_own          = {1, 0, 0};
	ble_gap_sec_kdist_t kdist_peer         = {1, 1, 0};
	uint8_t             auth_status        = BLE_GAP_SEC_STATUS_SUCCESS;

	p_auth_status_evt = auth_status_evt(m_arbitrary_conn_handle, auth_status, false, kdist_own, kdist_peer);

	sec_proc_expect_end();
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_peer_id);

	smd_ble_evt_handler(p_auth_status_evt);

	TEST_ASSERT_EQUAL_UINT32(1 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	TEST_ASSERT_EQUAL_UINT32(PM_EVT_CONN_SEC_SUCCEEDED, m_evt_handler_records[0].evt_id);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_conn_handle, m_evt_handler_records[0].conn_handle);
	TEST_ASSERT_EQUAL(PM_CONN_SEC_PROCEDURE_PAIRING, m_evt_handler_records[0].params.conn_sec_succeeded.procedure);
	TEST_ASSERT_EQUAL_UINT32(false, m_evt_handler_records[0].params.conn_sec_succeeded.data_stored);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_peer_id, m_evt_handler_records[0 * SMD_EVENT_HANDLERS_CNT].peer_id);
	evt_handler_call_record_clear();


	/* Success - Known peer */
	auth_status        = BLE_GAP_SEC_STATUS_SUCCESS;
	pm_peer_data_t bonding_data;

	bonding_data.p_bonding_data = &m_arbitrary_bonding_data;

	p_auth_status_evt = auth_status_evt(m_arbitrary_conn_handle, auth_status, true, kdist_own, kdist_peer);

	sec_proc_expect_end();
	__cmock_pdb_write_buf_get_ExpectAndReturn(PDB_TEMP_PEER_ID(m_arbitrary_conn_handle), PM_PEER_DATA_ID_BONDING, 1, NULL, NRF_SUCCESS);
	__cmock_pdb_write_buf_get_IgnoreArg_p_peer_data();
	__cmock_pdb_write_buf_get_ReturnThruPtr_p_peer_data(&bonding_data);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_peer_id);
	__cmock_pdb_write_buf_store_ExpectAndReturn(PDB_TEMP_PEER_ID(m_arbitrary_conn_handle), PM_PEER_DATA_ID_BONDING, m_arbitrary_peer_id, NRF_SUCCESS);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_peer_id);

	smd_ble_evt_handler(p_auth_status_evt);

	TEST_ASSERT_EQUAL_UINT32(1 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	TEST_ASSERT_EQUAL_UINT32(PM_EVT_CONN_SEC_SUCCEEDED, m_evt_handler_records[0].evt_id);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_conn_handle, m_evt_handler_records[0].conn_handle);
	TEST_ASSERT_EQUAL(PM_CONN_SEC_PROCEDURE_BONDING, m_evt_handler_records[0].params.conn_sec_succeeded.procedure);
	TEST_ASSERT_EQUAL_UINT32(true, m_evt_handler_records[0].params.conn_sec_succeeded.data_stored);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_peer_id, m_evt_handler_records[0 * SMD_EVENT_HANDLERS_CNT].peer_id);
	evt_handler_call_record_clear();


	/* Success - new peer */
	auth_status        = BLE_GAP_SEC_STATUS_SUCCESS;

	p_auth_status_evt = auth_status_evt(m_arbitrary_conn_handle, auth_status, true, kdist_own, kdist_peer);

	sec_proc_expect_end();
	__cmock_pdb_write_buf_get_ExpectAndReturn(PDB_TEMP_PEER_ID(m_arbitrary_conn_handle), PM_PEER_DATA_ID_BONDING, 1, NULL, NRF_SUCCESS);
	__cmock_pdb_write_buf_get_IgnoreArg_p_peer_data();
	__cmock_pdb_write_buf_get_ReturnThruPtr_p_peer_data(&bonding_data);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, PM_PEER_ID_INVALID);
	__cmock_im_find_duplicate_bonding_data_ExpectAndReturn(&m_arbitrary_bonding_data, PM_PEER_ID_INVALID, PM_PEER_ID_INVALID);
	__cmock_pds_peer_id_allocate_ExpectAndReturn(m_arbitrary_peer_id);
	__cmock_im_new_peer_id_Expect(m_arbitrary_conn_handle, m_arbitrary_peer_id);
	__cmock_pdb_write_buf_store_ExpectAndReturn(PDB_TEMP_PEER_ID(m_arbitrary_conn_handle), PM_PEER_DATA_ID_BONDING, m_arbitrary_peer_id, NRF_SUCCESS);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_peer_id);

	smd_ble_evt_handler(p_auth_status_evt);

	TEST_ASSERT_EQUAL_UINT32(1 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	TEST_ASSERT_EQUAL_UINT32(PM_EVT_CONN_SEC_SUCCEEDED, m_evt_handler_records[0].evt_id);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_conn_handle, m_evt_handler_records[0].conn_handle);
	TEST_ASSERT_EQUAL(PM_CONN_SEC_PROCEDURE_BONDING, m_evt_handler_records[0].params.conn_sec_succeeded.procedure);
	TEST_ASSERT_EQUAL_UINT32(true, m_evt_handler_records[0].params.conn_sec_succeeded.data_stored);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_peer_id, m_evt_handler_records[0 * SMD_EVENT_HANDLERS_CNT].peer_id);
	evt_handler_call_record_clear();


	/* Success - duplicate - reject */
	auth_status        = BLE_GAP_SEC_STATUS_SUCCESS;
	p_auth_status_evt = auth_status_evt(m_arbitrary_conn_handle, auth_status, true, kdist_own, kdist_peer);

	sec_proc_expect_end();
	__cmock_pdb_write_buf_get_ExpectAndReturn(PDB_TEMP_PEER_ID(m_arbitrary_conn_handle), PM_PEER_DATA_ID_BONDING, 1, NULL, NRF_SUCCESS);
	__cmock_pdb_write_buf_get_IgnoreArg_p_peer_data();
	__cmock_pdb_write_buf_get_ReturnThruPtr_p_peer_data(&bonding_data);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, PM_PEER_ID_INVALID);
	__cmock_im_find_duplicate_bonding_data_ExpectAndReturn(&m_arbitrary_bonding_data, PM_PEER_ID_INVALID, m_arbitrary_peer_id);
	__cmock_im_new_peer_id_Expect(m_arbitrary_conn_handle, m_arbitrary_peer_id);
	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_flag_id_allow, false);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_peer_id);
	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_flag_id_allow, false);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_peer_id);

	smd_ble_evt_handler(p_auth_status_evt);

	TEST_ASSERT_EQUAL_UINT32(2 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	TEST_ASSERT_EQUAL_UINT32(PM_EVT_CONN_SEC_CONFIG_REQ, m_evt_handler_records[0].evt_id);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_conn_handle, m_evt_handler_records[0].conn_handle);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_peer_id, m_evt_handler_records[0 * SMD_EVENT_HANDLERS_CNT].peer_id);
	TEST_ASSERT_EQUAL_UINT32(PM_EVT_CONN_SEC_SUCCEEDED, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].evt_id);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_conn_handle, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].conn_handle);
	TEST_ASSERT_EQUAL(PM_CONN_SEC_PROCEDURE_BONDING, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].params.conn_sec_succeeded.procedure);
	TEST_ASSERT_EQUAL_UINT32(false, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].params.conn_sec_succeeded.data_stored);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_peer_id, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].peer_id);

	evt_handler_call_record_clear();


	/* Success - duplicate - keep */
	auth_status                            = BLE_GAP_SEC_STATUS_SUCCESS;
	p_auth_status_evt                      = auth_status_evt(m_arbitrary_conn_handle, auth_status, true, kdist_own, kdist_peer);
	m_reject_pairing                       = false;

	sec_proc_expect_end();
	__cmock_pdb_write_buf_get_ExpectAndReturn(PDB_TEMP_PEER_ID(m_arbitrary_conn_handle), PM_PEER_DATA_ID_BONDING, 1, NULL, NRF_SUCCESS);
	__cmock_pdb_write_buf_get_IgnoreArg_p_peer_data();
	__cmock_pdb_write_buf_get_ReturnThruPtr_p_peer_data(&bonding_data);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, PM_PEER_ID_INVALID);
	__cmock_im_find_duplicate_bonding_data_ExpectAndReturn(&m_arbitrary_bonding_data, PM_PEER_ID_INVALID, m_arbitrary_peer_id);
	__cmock_im_new_peer_id_Expect(m_arbitrary_conn_handle, m_arbitrary_peer_id);
	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_flag_id_allow, false);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_peer_id);
	__cmock_ble_conn_state_user_flag_set_Expect(m_arbitrary_conn_handle, m_arbitrary_flag_id_allow, true);
	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_flag_id_allow, true);
	__cmock_pdb_write_buf_store_ExpectAndReturn(PDB_TEMP_PEER_ID(m_arbitrary_conn_handle), PM_PEER_DATA_ID_BONDING, m_arbitrary_peer_id, NRF_SUCCESS);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_peer_id);

	smd_ble_evt_handler(p_auth_status_evt);

	TEST_ASSERT_EQUAL_UINT32(2 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	TEST_ASSERT_EQUAL_UINT32(PM_EVT_CONN_SEC_CONFIG_REQ, m_evt_handler_records[0].evt_id);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_conn_handle, m_evt_handler_records[0].conn_handle);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_peer_id, m_evt_handler_records[0 * SMD_EVENT_HANDLERS_CNT].peer_id);
	TEST_ASSERT_EQUAL_UINT32(PM_EVT_CONN_SEC_SUCCEEDED, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].evt_id);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_conn_handle, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].conn_handle);
	TEST_ASSERT_EQUAL(PM_CONN_SEC_PROCEDURE_BONDING, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].params.conn_sec_succeeded.procedure);
	TEST_ASSERT_EQUAL_UINT32(true, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].params.conn_sec_succeeded.data_stored);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_peer_id, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].peer_id);

	evt_handler_call_record_clear();
	m_reject_pairing                       = true;


	/* Success - duplicate - already approved */
	auth_status                            = BLE_GAP_SEC_STATUS_SUCCESS;
	p_auth_status_evt                      = auth_status_evt(m_arbitrary_conn_handle, auth_status, true, kdist_own, kdist_peer);
	m_reject_pairing                       = false;

	sec_proc_expect_end();
	__cmock_pdb_write_buf_get_ExpectAndReturn(PDB_TEMP_PEER_ID(m_arbitrary_conn_handle), PM_PEER_DATA_ID_BONDING, 1, NULL, NRF_SUCCESS);
	__cmock_pdb_write_buf_get_IgnoreArg_p_peer_data();
	__cmock_pdb_write_buf_get_ReturnThruPtr_p_peer_data(&bonding_data);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, PM_PEER_ID_INVALID);
	__cmock_im_find_duplicate_bonding_data_ExpectAndReturn(&m_arbitrary_bonding_data, PM_PEER_ID_INVALID, m_arbitrary_peer_id);
	__cmock_im_new_peer_id_Expect(m_arbitrary_conn_handle, m_arbitrary_peer_id);
	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_flag_id_allow, true);
	__cmock_pdb_write_buf_store_ExpectAndReturn(PDB_TEMP_PEER_ID(m_arbitrary_conn_handle), PM_PEER_DATA_ID_BONDING, m_arbitrary_peer_id, NRF_SUCCESS);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_peer_id);

	smd_ble_evt_handler(p_auth_status_evt);

	TEST_ASSERT_EQUAL_UINT32(1 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	TEST_ASSERT_EQUAL_UINT32(PM_EVT_CONN_SEC_SUCCEEDED, m_evt_handler_records[0 * SMD_EVENT_HANDLERS_CNT].evt_id);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_conn_handle, m_evt_handler_records[0 * SMD_EVENT_HANDLERS_CNT].conn_handle);
	TEST_ASSERT_EQUAL(PM_CONN_SEC_PROCEDURE_BONDING, m_evt_handler_records[0 * SMD_EVENT_HANDLERS_CNT].params.conn_sec_succeeded.procedure);
	TEST_ASSERT_EQUAL_UINT32(true, m_evt_handler_records[0 * SMD_EVENT_HANDLERS_CNT].params.conn_sec_succeeded.data_stored);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_peer_id, m_evt_handler_records[0 * SMD_EVENT_HANDLERS_CNT].peer_id);

	evt_handler_call_record_clear();
	m_reject_pairing                       = true;


	/* Success - write_buf_get Failed. */
	auth_status                            = BLE_GAP_SEC_STATUS_SUCCESS;
	p_auth_status_evt                      = auth_status_evt(m_arbitrary_conn_handle, auth_status, true, kdist_own, kdist_peer);

	sec_proc_expect_end();
	__cmock_pdb_write_buf_get_ExpectAndReturn(PDB_TEMP_PEER_ID(m_arbitrary_conn_handle), PM_PEER_DATA_ID_BONDING, 1, NULL, NRF_ERROR_INTERNAL);
	__cmock_pdb_write_buf_get_IgnoreArg_p_peer_data();
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_peer_id);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_peer_id);

	smd_ble_evt_handler(p_auth_status_evt);

	TEST_ASSERT_EQUAL_UINT32(2 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	TEST_ASSERT_EQUAL_UINT32(PM_EVT_ERROR_UNEXPECTED, m_evt_handler_records[0].evt_id);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_conn_handle, m_evt_handler_records[0].conn_handle);
	TEST_ASSERT_EQUAL_UINT32(NRF_ERROR_INTERNAL, m_evt_handler_records[0].params.error_unexpected.error);
	TEST_ASSERT_EQUAL_UINT32(PM_EVT_CONN_SEC_SUCCEEDED, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].evt_id);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_conn_handle, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].conn_handle);
	TEST_ASSERT_EQUAL(PM_CONN_SEC_PROCEDURE_BONDING, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].params.conn_sec_succeeded.procedure);
	TEST_ASSERT_EQUAL_UINT32(false, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].params.conn_sec_succeeded.data_stored);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_peer_id, m_evt_handler_records[0 * SMD_EVENT_HANDLERS_CNT].peer_id);

	evt_handler_call_record_clear();


	/* Success - allocate failed. */
	sec_proc_expect_end();
	__cmock_pdb_write_buf_get_ExpectAndReturn(PDB_TEMP_PEER_ID(m_arbitrary_conn_handle), PM_PEER_DATA_ID_BONDING, 1, NULL, NRF_SUCCESS);
	__cmock_pdb_write_buf_get_IgnoreArg_p_peer_data();
	__cmock_pdb_write_buf_get_ReturnThruPtr_p_peer_data(&bonding_data);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, PM_PEER_ID_INVALID);
	__cmock_im_find_duplicate_bonding_data_ExpectAndReturn(&m_arbitrary_bonding_data, PM_PEER_ID_INVALID, PM_PEER_ID_INVALID);
	__cmock_pds_peer_id_allocate_ExpectAndReturn(PM_PEER_ID_INVALID);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_peer_id);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_peer_id);

	smd_ble_evt_handler(p_auth_status_evt);

	TEST_ASSERT_EQUAL_UINT32(2 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	TEST_ASSERT_EQUAL_UINT32(PM_EVT_ERROR_UNEXPECTED, m_evt_handler_records[0].evt_id);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_conn_handle, m_evt_handler_records[0].conn_handle);
	TEST_ASSERT_EQUAL_UINT32(NRF_ERROR_NO_MEM, m_evt_handler_records[0].params.error_unexpected.error);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_peer_id, m_evt_handler_records[0 * SMD_EVENT_HANDLERS_CNT].peer_id);
	TEST_ASSERT_EQUAL_UINT32(PM_EVT_CONN_SEC_SUCCEEDED, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].evt_id);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_conn_handle, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].conn_handle);
	TEST_ASSERT_EQUAL(PM_CONN_SEC_PROCEDURE_BONDING, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].params.conn_sec_succeeded.procedure);
	TEST_ASSERT_EQUAL_UINT32(false, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].params.conn_sec_succeeded.data_stored);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_peer_id, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].peer_id);

	evt_handler_call_record_clear();

#if defined(BLE_GAP_ROLE_CENTRAL)
	/* Success - Store Failed - Flash full. */
	sec_proc_expect_end();
	__cmock_pdb_write_buf_get_ExpectAndReturn(PDB_TEMP_PEER_ID(m_arbitrary_conn_handle), PM_PEER_DATA_ID_BONDING, 1, NULL, NRF_SUCCESS);
	__cmock_pdb_write_buf_get_IgnoreArg_p_peer_data();
	__cmock_pdb_write_buf_get_ReturnThruPtr_p_peer_data(&bonding_data);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, PM_PEER_ID_INVALID);
	__cmock_im_find_duplicate_bonding_data_ExpectAndReturn(&m_arbitrary_bonding_data, PM_PEER_ID_INVALID, PM_PEER_ID_INVALID);
	__cmock_pds_peer_id_allocate_ExpectAndReturn(m_arbitrary_peer_id);
	__cmock_im_new_peer_id_Expect(m_arbitrary_conn_handle, m_arbitrary_peer_id);
	__cmock_pdb_write_buf_store_ExpectAndReturn(PDB_TEMP_PEER_ID(m_arbitrary_conn_handle), PM_PEER_DATA_ID_BONDING, m_arbitrary_peer_id, NRF_ERROR_NO_MEM);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_peer_id);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_peer_id);

	smd_ble_evt_handler(p_auth_status_evt);

	TEST_ASSERT_EQUAL_UINT32(2 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	TEST_ASSERT_EQUAL_UINT32(PM_EVT_STORAGE_FULL, m_evt_handler_records[0].evt_id);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_conn_handle, m_evt_handler_records[0].conn_handle);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_peer_id, m_evt_handler_records[0 * SMD_EVENT_HANDLERS_CNT].peer_id);
	TEST_ASSERT_EQUAL_UINT32(PM_EVT_CONN_SEC_SUCCEEDED, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].evt_id);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_conn_handle, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].conn_handle);
	TEST_ASSERT_EQUAL(PM_CONN_SEC_PROCEDURE_BONDING, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].params.conn_sec_succeeded.procedure);
	TEST_ASSERT_EQUAL_UINT32(true, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].params.conn_sec_succeeded.data_stored);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_peer_id, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].peer_id);

	evt_handler_call_record_clear();
#endif

	/* Success - Store Failed. */
	sec_proc_expect_end();
	__cmock_pdb_write_buf_get_ExpectAndReturn(PDB_TEMP_PEER_ID(m_arbitrary_conn_handle), PM_PEER_DATA_ID_BONDING, 1, NULL, NRF_SUCCESS);
	__cmock_pdb_write_buf_get_IgnoreArg_p_peer_data();
	__cmock_pdb_write_buf_get_ReturnThruPtr_p_peer_data(&bonding_data);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_peer_id);
	__cmock_pdb_write_buf_store_ExpectAndReturn(PDB_TEMP_PEER_ID(m_arbitrary_conn_handle), PM_PEER_DATA_ID_BONDING, m_arbitrary_peer_id, NRF_ERROR_NOT_FOUND);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_peer_id);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_peer_id);

	smd_ble_evt_handler(p_auth_status_evt);

	TEST_ASSERT_EQUAL_UINT32(2 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	TEST_ASSERT_EQUAL_UINT32(PM_EVT_ERROR_UNEXPECTED, m_evt_handler_records[0].evt_id);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_conn_handle, m_evt_handler_records[0].conn_handle);
	TEST_ASSERT_EQUAL_UINT32(NRF_ERROR_NOT_FOUND, m_evt_handler_records[0].params.error_unexpected.error);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_peer_id, m_evt_handler_records[0].peer_id);
	TEST_ASSERT_EQUAL_UINT32(PM_EVT_CONN_SEC_SUCCEEDED, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].evt_id);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_conn_handle, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].conn_handle);
	TEST_ASSERT_EQUAL(PM_CONN_SEC_PROCEDURE_BONDING, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].params.conn_sec_succeeded.procedure);
	TEST_ASSERT_EQUAL_UINT32(false, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].params.conn_sec_succeeded.data_stored);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_peer_id, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].peer_id);

	evt_handler_call_record_clear();


	/* Success - Store Failed - free */
	sec_proc_expect_end();
	__cmock_pdb_write_buf_get_ExpectAndReturn(PDB_TEMP_PEER_ID(m_arbitrary_conn_handle), PM_PEER_DATA_ID_BONDING, 1, NULL, NRF_SUCCESS);
	__cmock_pdb_write_buf_get_IgnoreArg_p_peer_data();
	__cmock_pdb_write_buf_get_ReturnThruPtr_p_peer_data(&bonding_data);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, PM_PEER_ID_INVALID);
	__cmock_im_find_duplicate_bonding_data_ExpectAndReturn(&m_arbitrary_bonding_data, PM_PEER_ID_INVALID, PM_PEER_ID_INVALID);
	__cmock_pds_peer_id_allocate_ExpectAndReturn(m_arbitrary_peer_id);
	__cmock_im_new_peer_id_Expect(m_arbitrary_conn_handle, m_arbitrary_peer_id);
	__cmock_pdb_write_buf_store_ExpectAndReturn(PDB_TEMP_PEER_ID(m_arbitrary_conn_handle), PM_PEER_DATA_ID_BONDING, m_arbitrary_peer_id, NRF_ERROR_INTERNAL);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_peer_id);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_peer_id);
	__cmock_im_peer_free_ExpectAndReturn(m_arbitrary_peer_id, NRF_SUCCESS);

	smd_ble_evt_handler(p_auth_status_evt);

	TEST_ASSERT_EQUAL_UINT32(2 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	TEST_ASSERT_EQUAL_UINT32(PM_EVT_ERROR_UNEXPECTED, m_evt_handler_records[0].evt_id);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_conn_handle, m_evt_handler_records[0].conn_handle);
	TEST_ASSERT_EQUAL_UINT32(NRF_ERROR_INTERNAL, m_evt_handler_records[0].params.error_unexpected.error);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_peer_id, m_evt_handler_records[0].peer_id);
	TEST_ASSERT_EQUAL_UINT32(PM_EVT_CONN_SEC_SUCCEEDED, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].evt_id);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_conn_handle, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].conn_handle);
	TEST_ASSERT_EQUAL(PM_CONN_SEC_PROCEDURE_BONDING, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].params.conn_sec_succeeded.procedure);
	TEST_ASSERT_EQUAL_UINT32(false, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].params.conn_sec_succeeded.data_stored);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_peer_id, m_evt_handler_records[1 * SMD_EVENT_HANDLERS_CNT].peer_id);

	evt_handler_call_record_clear();


	/* Failure, release. */
	auth_status = BLE_GAP_SEC_STATUS_PAIRING_NOT_SUPP;

	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_flag_id_sec_proc, true);
	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_flag_id_pairing, true);
	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_flag_id_bonding, true);
	__cmock_pdb_write_buf_release_ExpectAndReturn(PDB_TEMP_PEER_ID(m_arbitrary_conn_handle), PM_PEER_DATA_ID_BONDING, NRF_SUCCESS);
	sec_proc_expect_fail(m_arbitrary_peer_id);

	smd_ble_evt_handler(auth_status_evt(m_arbitrary_conn_handle, auth_status, true, kdist_own, kdist_peer));

	TEST_ASSERT_EQUAL_UINT32(1 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	TEST_ASSERT_EQUAL_UINT32(PM_EVT_CONN_SEC_FAILED, m_evt_handler_records[0].evt_id);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_conn_handle, m_evt_handler_records[0].conn_handle);
	TEST_ASSERT_EQUAL_UINT32(auth_status, m_evt_handler_records[0].params.conn_sec_failed.error);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_peer_id, m_evt_handler_records[0 * SMD_EVENT_HANDLERS_CNT].peer_id);
	evt_handler_call_record_clear();


	/* Failure, pairing only */
	auth_status = BLE_GAP_SEC_STATUS_PAIRING_NOT_SUPP;

	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_flag_id_sec_proc, true);
	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_flag_id_pairing, true);
	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_flag_id_bonding, true);
	__cmock_pdb_write_buf_release_ExpectAndReturn(PDB_TEMP_PEER_ID(m_arbitrary_conn_handle), PM_PEER_DATA_ID_BONDING, NRF_SUCCESS);
	sec_proc_expect_fail(PM_PEER_ID_INVALID);

	smd_ble_evt_handler(auth_status_evt(m_arbitrary_conn_handle, auth_status, true, kdist_own, kdist_peer));

	TEST_ASSERT_EQUAL_UINT32(1 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	TEST_ASSERT_EQUAL_UINT32(PM_EVT_CONN_SEC_FAILED, m_evt_handler_records[0].evt_id);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_conn_handle, m_evt_handler_records[0].conn_handle);
	TEST_ASSERT_EQUAL_UINT32(auth_status, m_evt_handler_records[0].params.conn_sec_failed.error);
	TEST_ASSERT_EQUAL_UINT32(PM_PEER_ID_INVALID, m_evt_handler_records[0 * SMD_EVENT_HANDLERS_CNT].peer_id);
	evt_handler_call_record_clear();


	/* Invalid PDU */
	auth_status = BLE_GAP_SEC_STATUS_PDU_INVALID;

	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_flag_id_sec_proc, false);

	smd_ble_evt_handler(auth_status_evt(m_arbitrary_conn_handle, auth_status, true, kdist_own, kdist_peer));

	TEST_ASSERT_EQUAL_UINT32(0, m_n_evt_handler_calls);
	evt_handler_call_record_clear();

#if defined(BLE_GAP_ROLE_CENTRAL)
	/* Sec request. */
	uint8_t bond = 0;
	uint8_t mitm = 0;

	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_flag_id_sec_proc, true);
	smd_ble_evt_handler(sec_request_evt(m_arbitrary_conn_handle, bond, mitm));
	TEST_ASSERT_EQUAL_UINT32(0, m_n_evt_handler_calls);

	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_flag_id_sec_proc, false);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, PM_PEER_ID_INVALID);
	smd_ble_evt_handler(sec_request_evt(m_arbitrary_conn_handle, bond, mitm));
	TEST_ASSERT_EQUAL_UINT32(1, m_n_evt_handler_calls);
	TEST_ASSERT_EQUAL_UINT32(PM_EVT_SLAVE_SECURITY_REQ, m_evt_handler_records[0].evt_id);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_conn_handle,   m_evt_handler_records[0].conn_handle);

	TEST_ASSERT_EQUAL_UINT32(bond, m_evt_handler_records[0].params.slave_security_req.bond);
	TEST_ASSERT_EQUAL_UINT32(mitm, m_evt_handler_records[0].params.slave_security_req.mitm);

	TEST_ASSERT_EQUAL_UINT32(PM_PEER_ID_INVALID, m_evt_handler_records[0 * SMD_EVENT_HANDLERS_CNT].peer_id);
	evt_handler_call_record_clear();

	bond = 0;
	mitm = 1;
	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_flag_id_sec_proc, false);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_peer_id);
	smd_ble_evt_handler(sec_request_evt(m_arbitrary_conn_handle, bond, mitm));
	TEST_ASSERT_EQUAL_UINT32(1, m_n_evt_handler_calls);
	TEST_ASSERT_EQUAL_UINT32(PM_EVT_SLAVE_SECURITY_REQ, m_evt_handler_records[0].evt_id);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_conn_handle,   m_evt_handler_records[0].conn_handle);

	TEST_ASSERT_EQUAL_UINT32(bond, m_evt_handler_records[0].params.slave_security_req.bond);
	TEST_ASSERT_EQUAL_UINT32(mitm, m_evt_handler_records[0].params.slave_security_req.mitm);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_peer_id, m_evt_handler_records[0 * SMD_EVENT_HANDLERS_CNT].peer_id);
	evt_handler_call_record_clear();

	bond = 1;
	mitm = 0;
	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_flag_id_sec_proc, false);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_peer_id);
	smd_ble_evt_handler(sec_request_evt(m_arbitrary_conn_handle, bond, mitm));
	TEST_ASSERT_EQUAL_UINT32(1, m_n_evt_handler_calls);
	TEST_ASSERT_EQUAL_UINT32(PM_EVT_SLAVE_SECURITY_REQ, m_evt_handler_records[0].evt_id);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_conn_handle,   m_evt_handler_records[0].conn_handle);
	TEST_ASSERT_EQUAL_UINT32(bond, m_evt_handler_records[0].params.slave_security_req.bond);
	TEST_ASSERT_EQUAL_UINT32(mitm, m_evt_handler_records[0].params.slave_security_req.mitm);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_peer_id, m_evt_handler_records[0 * SMD_EVENT_HANDLERS_CNT].peer_id);
	evt_handler_call_record_clear();

	bond = 1;
	mitm = 1;
	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_flag_id_sec_proc, false);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_peer_id);
	smd_ble_evt_handler(sec_request_evt(m_arbitrary_conn_handle, bond, mitm));
	TEST_ASSERT_EQUAL_UINT32(1, m_n_evt_handler_calls);
	TEST_ASSERT_EQUAL_UINT32(PM_EVT_SLAVE_SECURITY_REQ, m_evt_handler_records[0].evt_id);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_conn_handle,   m_evt_handler_records[0].conn_handle);
	TEST_ASSERT_EQUAL_UINT32(bond, m_evt_handler_records[0].params.slave_security_req.bond);
	TEST_ASSERT_EQUAL_UINT32(mitm, m_evt_handler_records[0].params.slave_security_req.mitm);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_peer_id, m_evt_handler_records[0 * SMD_EVENT_HANDLERS_CNT].peer_id);
	evt_handler_call_record_clear();
#endif

	/* Disconnected */
	/* MIC Failure */
	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_flag_id_sec_proc, true);
	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_flag_id_pairing,  false);
	sec_proc_expect_end();
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_peer_id);

	smd_ble_evt_handler(disconnected_evt(m_arbitrary_conn_handle, BLE_HCI_CONN_TERMINATED_DUE_TO_MIC_FAILURE));
	TEST_ASSERT_EQUAL_UINT32(1 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	TEST_ASSERT_EQUAL_UINT32(PM_EVT_CONN_SEC_FAILED, m_evt_handler_records[0].evt_id);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_conn_handle, m_evt_handler_records[0].conn_handle);
	TEST_ASSERT_EQUAL_UINT32(PM_CONN_SEC_PROCEDURE_ENCRYPTION, m_evt_handler_records[0].params.conn_sec_failed.procedure);
	TEST_ASSERT_EQUAL_UINT32(PM_CONN_SEC_ERROR_MIC_FAILURE, m_evt_handler_records[0].params.conn_sec_failed.error);
	TEST_ASSERT_EQUAL_UINT32(BLE_GAP_SEC_STATUS_SOURCE_LOCAL, m_evt_handler_records[0].params.conn_sec_failed.error_src);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_peer_id, m_evt_handler_records[0 * SMD_EVENT_HANDLERS_CNT].peer_id);
	evt_handler_call_record_clear();

	/* Other reason - encryption */
	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_flag_id_sec_proc, true);
	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_flag_id_pairing,  false);
	sec_proc_expect_end();
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_peer_id);

	smd_ble_evt_handler(disconnected_evt(m_arbitrary_conn_handle, BLE_HCI_CONN_TERMINATED_DUE_TO_MIC_FAILURE + 1));
	TEST_ASSERT_EQUAL_UINT32(1 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	TEST_ASSERT_EQUAL_UINT32(PM_EVT_CONN_SEC_FAILED, m_evt_handler_records[0].evt_id);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_conn_handle, m_evt_handler_records[0].conn_handle);
	TEST_ASSERT_EQUAL_UINT32(PM_CONN_SEC_PROCEDURE_ENCRYPTION, m_evt_handler_records[0].params.conn_sec_failed.procedure);
	TEST_ASSERT_EQUAL_UINT32(PM_CONN_SEC_ERROR_DISCONNECT, m_evt_handler_records[0].params.conn_sec_failed.error);
	TEST_ASSERT_EQUAL_UINT32(BLE_GAP_SEC_STATUS_SOURCE_LOCAL, m_evt_handler_records[0].params.conn_sec_failed.error_src);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_peer_id, m_evt_handler_records[0 * SMD_EVENT_HANDLERS_CNT].peer_id);
	evt_handler_call_record_clear();

	/* Other reason - pairing */
	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_flag_id_sec_proc, true);
	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_flag_id_pairing,  true);
	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_flag_id_bonding,  false);
	__cmock_pdb_write_buf_release_ExpectAndReturn(PDB_TEMP_PEER_ID(m_arbitrary_conn_handle), PM_PEER_DATA_ID_BONDING, NRF_SUCCESS);
	sec_proc_expect_end();
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_peer_id);

	smd_ble_evt_handler(disconnected_evt(m_arbitrary_conn_handle, BLE_HCI_CONN_TERMINATED_DUE_TO_MIC_FAILURE + 1));
	TEST_ASSERT_EQUAL_UINT32(1 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	TEST_ASSERT_EQUAL_UINT32(PM_EVT_CONN_SEC_FAILED, m_evt_handler_records[0].evt_id);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_conn_handle, m_evt_handler_records[0].conn_handle);
	TEST_ASSERT_EQUAL_UINT32(PM_CONN_SEC_PROCEDURE_PAIRING, m_evt_handler_records[0].params.conn_sec_failed.procedure);
	TEST_ASSERT_EQUAL_UINT32(PM_CONN_SEC_ERROR_DISCONNECT, m_evt_handler_records[0].params.conn_sec_failed.error);
	TEST_ASSERT_EQUAL_UINT32(BLE_GAP_SEC_STATUS_SOURCE_LOCAL, m_evt_handler_records[0].params.conn_sec_failed.error_src);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_peer_id, m_evt_handler_records[0 * SMD_EVENT_HANDLERS_CNT].peer_id);
	evt_handler_call_record_clear();

	/* Other reason - pairing - write_buf_release NOT_FOUND (not error condition) */
	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_flag_id_sec_proc, true);
	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_flag_id_pairing,  true);
	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_flag_id_bonding,  false);
	__cmock_pdb_write_buf_release_ExpectAndReturn(PDB_TEMP_PEER_ID(m_arbitrary_conn_handle), PM_PEER_DATA_ID_BONDING, NRF_ERROR_NOT_FOUND);
	sec_proc_expect_end();
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_peer_id);

	smd_ble_evt_handler(disconnected_evt(m_arbitrary_conn_handle, BLE_HCI_CONN_TERMINATED_DUE_TO_MIC_FAILURE + 1));
	TEST_ASSERT_EQUAL_UINT32(1 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	TEST_ASSERT_EQUAL_UINT32(PM_EVT_CONN_SEC_FAILED, m_evt_handler_records[0].evt_id);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_conn_handle, m_evt_handler_records[0].conn_handle);
	TEST_ASSERT_EQUAL_UINT32(PM_CONN_SEC_PROCEDURE_PAIRING, m_evt_handler_records[0].params.conn_sec_failed.procedure);
	TEST_ASSERT_EQUAL_UINT32(PM_CONN_SEC_ERROR_DISCONNECT, m_evt_handler_records[0].params.conn_sec_failed.error);
	TEST_ASSERT_EQUAL_UINT32(BLE_GAP_SEC_STATUS_SOURCE_LOCAL, m_evt_handler_records[0].params.conn_sec_failed.error_src);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_peer_id, m_evt_handler_records[0 * SMD_EVENT_HANDLERS_CNT].peer_id);
	evt_handler_call_record_clear();

	/* Other reason - pairing - write_buf_release INTERNAL ( error condition) */
	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_flag_id_sec_proc, true);
	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_flag_id_pairing,  true);
	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_flag_id_bonding,  true);
	__cmock_pdb_write_buf_release_ExpectAndReturn(PDB_TEMP_PEER_ID(m_arbitrary_conn_handle), PM_PEER_DATA_ID_BONDING, NRF_ERROR_INTERNAL);
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_peer_id);
	sec_proc_expect_end();
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_peer_id);

	smd_ble_evt_handler(disconnected_evt(m_arbitrary_conn_handle, BLE_HCI_CONN_TERMINATED_DUE_TO_MIC_FAILURE + 1));
	TEST_ASSERT_EQUAL_UINT32(2 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	TEST_ASSERT_EQUAL_UINT32(PM_EVT_ERROR_UNEXPECTED, m_evt_handler_records[0].evt_id);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_conn_handle, m_evt_handler_records[0].conn_handle);
	TEST_ASSERT_EQUAL_UINT32(NRF_ERROR_INTERNAL, m_evt_handler_records[0].params.error_unexpected.error);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_peer_id, m_evt_handler_records[0 * SMD_EVENT_HANDLERS_CNT].peer_id);
	TEST_ASSERT_EQUAL_UINT32(PM_EVT_CONN_SEC_FAILED, m_evt_handler_records[1].evt_id);
	TEST_ASSERT_EQUAL_UINT32(PM_CONN_SEC_PROCEDURE_BONDING, m_evt_handler_records[1].params.conn_sec_failed.procedure);
	evt_handler_call_record_clear();

	/* Other reason - pairing - new peer */
	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_flag_id_sec_proc, true);
	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_flag_id_pairing,  true);
	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_flag_id_bonding,  true);
	__cmock_pdb_write_buf_release_ExpectAndReturn(PDB_TEMP_PEER_ID(m_arbitrary_conn_handle), PM_PEER_DATA_ID_BONDING, NRF_ERROR_NOT_FOUND);
	sec_proc_expect_end();
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_peer_id);

	smd_ble_evt_handler(disconnected_evt(m_arbitrary_conn_handle, BLE_HCI_CONN_TERMINATED_DUE_TO_MIC_FAILURE + 1));
	TEST_ASSERT_EQUAL_UINT32(1 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	TEST_ASSERT_EQUAL_UINT32(PM_EVT_CONN_SEC_FAILED, m_evt_handler_records[0].evt_id);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_conn_handle, m_evt_handler_records[0].conn_handle);
	TEST_ASSERT_EQUAL_UINT32(PM_CONN_SEC_PROCEDURE_BONDING, m_evt_handler_records[0].params.conn_sec_failed.procedure);
	TEST_ASSERT_EQUAL_UINT32(PM_CONN_SEC_ERROR_DISCONNECT, m_evt_handler_records[0].params.conn_sec_failed.error);
	TEST_ASSERT_EQUAL_UINT32(BLE_GAP_SEC_STATUS_SOURCE_LOCAL, m_evt_handler_records[0].params.conn_sec_failed.error_src);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_peer_id, m_evt_handler_records[0 * SMD_EVENT_HANDLERS_CNT].peer_id);
	evt_handler_call_record_clear();

	/* Other reason - no sec */
	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_flag_id_sec_proc, false);

	smd_ble_evt_handler(disconnected_evt(m_arbitrary_conn_handle, BLE_HCI_CONN_TERMINATED_DUE_TO_MIC_FAILURE + 1));
	TEST_ASSERT_EQUAL_UINT32(0, m_n_evt_handler_calls);


	/* conn sec update */
	/* Encryption failed. */
	bool encrypted    = false;
	bool pairing_proc = false;

	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_flag_id_pairing, pairing_proc);
	__cmock_ble_conn_state_encrypted_ExpectAndReturn(m_arbitrary_conn_handle, encrypted);
	sec_proc_expect_fail(m_arbitrary_peer_id);

	smd_ble_evt_handler(conn_sec_update_evt(m_arbitrary_conn_handle, 0));
	TEST_ASSERT_EQUAL_UINT32(1 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	TEST_ASSERT_EQUAL_UINT32(PM_EVT_CONN_SEC_FAILED, m_evt_handler_records[0].evt_id);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_conn_handle, m_evt_handler_records[0].conn_handle);
	TEST_ASSERT_EQUAL_UINT32(PM_CONN_SEC_ERROR_PIN_OR_KEY_MISSING, m_evt_handler_records[0].params.conn_sec_failed.error);
	TEST_ASSERT_EQUAL_UINT32(BLE_GAP_SEC_STATUS_SOURCE_REMOTE, m_evt_handler_records[0].params.conn_sec_failed.error_src);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_peer_id, m_evt_handler_records[0 * SMD_EVENT_HANDLERS_CNT].peer_id);
	evt_handler_call_record_clear();

	/* Encrypted, no MITM */
	encrypted = true;
	pairing_proc = false;

	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_flag_id_pairing, pairing_proc);
	__cmock_ble_conn_state_encrypted_ExpectAndReturn(m_arbitrary_conn_handle, encrypted);
	sec_proc_expect_end();
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_peer_id);

	smd_ble_evt_handler(conn_sec_update_evt(m_arbitrary_conn_handle, 1));
	TEST_ASSERT_EQUAL_UINT32(1 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	TEST_ASSERT_EQUAL_UINT32(PM_EVT_CONN_SEC_SUCCEEDED, m_evt_handler_records[0].evt_id);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_conn_handle,   m_evt_handler_records[0].conn_handle);
	TEST_ASSERT_EQUAL_UINT32(PM_CONN_SEC_PROCEDURE_ENCRYPTION, m_evt_handler_records[0].params.conn_sec_succeeded.procedure);
	TEST_ASSERT_EQUAL_UINT32(false, m_evt_handler_records[0].params.conn_sec_succeeded.data_stored);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_peer_id, m_evt_handler_records[0 * SMD_EVENT_HANDLERS_CNT].peer_id);
	evt_handler_call_record_clear();

	/* Encrypted as part of pairing */
	encrypted = true;
	pairing_proc = true;

	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_flag_id_pairing, pairing_proc);

	smd_ble_evt_handler(conn_sec_update_evt(m_arbitrary_conn_handle, 1));
	TEST_ASSERT_EQUAL_UINT32(0 * SMD_EVENT_HANDLERS_CNT, m_n_evt_handler_calls);
	evt_handler_call_record_clear();

	/* Encrypted, with MITM and multiple registrants. */
	encrypted = true;

	__cmock_ble_conn_state_user_flag_get_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_flag_id_pairing, false);
	__cmock_ble_conn_state_encrypted_ExpectAndReturn(m_arbitrary_conn_handle, encrypted);
	sec_proc_expect_end();
	__cmock_im_peer_id_get_by_conn_handle_ExpectAndReturn(m_arbitrary_conn_handle, m_arbitrary_peer_id);

	smd_ble_evt_handler(conn_sec_update_evt(m_arbitrary_conn_handle, 1));

	TEST_ASSERT_EQUAL_UINT32(PM_EVT_CONN_SEC_SUCCEEDED, m_evt_handler_records[0].evt_id);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_conn_handle,   m_evt_handler_records[0].conn_handle);
	TEST_ASSERT_EQUAL_UINT32(PM_CONN_SEC_PROCEDURE_ENCRYPTION, m_evt_handler_records[0].params.conn_sec_succeeded.procedure);
	TEST_ASSERT_EQUAL_UINT32(false, m_evt_handler_records[0].params.conn_sec_succeeded.data_stored);
	TEST_ASSERT_EQUAL_UINT32(m_arbitrary_peer_id, m_evt_handler_records[0 * SMD_EVENT_HANDLERS_CNT].peer_id);
	evt_handler_call_record_clear();
}


void test_smd_conn_sec_config_reply(void)
{
	pm_conn_sec_config_t config;

	config.allow_repairing = true;
	__cmock_ble_conn_state_user_flag_set_Expect(m_arbitrary_conn_handle, m_arbitrary_flag_id_allow, true);
	smd_conn_sec_config_reply(m_arbitrary_conn_handle, &config);

	config.allow_repairing = false;
	__cmock_ble_conn_state_user_flag_set_Expect(m_arbitrary_conn_handle, m_arbitrary_flag_id_allow, false);
	smd_conn_sec_config_reply(m_arbitrary_conn_handle, &config);
}

void tearDown(void)
{
	m_module_initialized     = false;

	memset(&m_peer_pk, 0x00, sizeof(m_peer_pk));

	m_flag_sec_proc          = -ENOSPC;
	m_flag_sec_proc_pairing  = -ENOSPC;
	m_flag_sec_proc_bonding  = -ENOSPC;
	m_flag_allow_repairing   = -ENOSPC;
}

void setUp(void)
{
	evt_handler_call_record_clear();
	__cmock_ble_conn_state_user_flag_acquire_ExpectAndReturn(m_arbitrary_flag_id_sec_proc);
	__cmock_ble_conn_state_user_flag_acquire_ExpectAndReturn(m_arbitrary_flag_id_pairing);
	__cmock_ble_conn_state_user_flag_acquire_ExpectAndReturn(m_arbitrary_flag_id_bonding);
	__cmock_ble_conn_state_user_flag_acquire_ExpectAndReturn(m_arbitrary_flag_id_allow);

	(void) smd_init();
}

extern int unity_main(void);

int main(void)
{
	return unity_main();
}
