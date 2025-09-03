/*
 * Copyright (c) 2015-2025 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <stdint.h>
#include <string.h>
#include <zephyr/logging/log.h>
#include <nrf_error.h>
#include <nordic_common.h>
#include <sdk_macros.h>
#include <bluetooth/peer_manager/peer_manager_types.h>
#include <bm_zms.h>
#include <modules/peer_manager_internal.h>
#include <modules/peer_id.h>
#include <modules/peer_data_storage.h>

LOG_MODULE_DECLARE(peer_manager, CONFIG_PEER_MANAGER_LOG_LEVEL);

/* Macro for verifying that the peer id is within a valid range. */
#define VERIFY_PEER_ID_IN_RANGE(id)                                                                \
	VERIFY_FALSE((id >= PM_PEER_ID_N_AVAILABLE_IDS), NRF_ERROR_INVALID_PARAM)

/* Macro for verifying that the peer data id is within a valid range. */
#define VERIFY_PEER_DATA_ID_IN_RANGE(id)                                                           \
	VERIFY_TRUE(peer_data_id_is_valid(id), NRF_ERROR_INVALID_PARAM)

/* The number of registered event handlers. */
#define PDS_EVENT_HANDLERS_CNT ARRAY_SIZE(m_evt_handlers)

/* Peer Data Storage event handler in Peer Database. */
extern void pdb_pds_evt_handler(pm_evt_t *evt);

/* Peer Data Storage events' handlers.
 * The number of elements in this array is PDS_EVENT_HANDLERS_CNT.
 */
static pm_evt_handler_internal_t const m_evt_handlers[] = {
	pdb_pds_evt_handler,
};

static bool m_module_initialized;
static volatile bool m_peer_delete_deferred;

static struct bm_zms_fs fs;

/* Function for dispatching events to all registered event handlers. */
static void pds_evt_send(pm_evt_t *p_event)
{
	p_event->conn_handle = BLE_CONN_HANDLE_INVALID;

	for (uint32_t i = 0; i < PDS_EVENT_HANDLERS_CNT; i++) {
		m_evt_handlers[i](p_event);
	}
}

static uint32_t peer_id_peer_data_id_to_entry_id(uint16_t peer_id,
						 pm_peer_data_id_t data_id)
{
	return (peer_id * PM_PEER_DATA_ID_LAST) + data_id;
}

static void entry_id_to_peer_id_peer_data_id(uint32_t entry_id, uint16_t *peer_id,
					     pm_peer_data_id_t *data_id)
{
	*data_id = entry_id % PM_PEER_DATA_ID_LAST;
	*peer_id = entry_id / PM_PEER_DATA_ID_LAST;
}

/* Function for checking whether a file ID is relevant for the Peer Manager. */
static bool file_id_within_pm_range(uint16_t file_id)
{
	return ((PDS_FIRST_RESERVED_FILE_ID <= file_id) && (file_id <= PDS_LAST_RESERVED_FILE_ID));
}

/* Function for checking whether a record key is relevant for the Peer Manager. */
static bool record_key_within_pm_range(uint16_t record_key)
{
	return ((PDS_FIRST_RESERVED_RECORD_KEY <= record_key) &&
		(record_key <= PDS_LAST_RESERVED_RECORD_KEY));
}

static bool peer_data_id_is_valid(pm_peer_data_id_t data_id)
{
	return ((data_id == PM_PEER_DATA_ID_BONDING) ||
		(data_id == PM_PEER_DATA_ID_SERVICE_CHANGED_PENDING) ||
		(data_id == PM_PEER_DATA_ID_GATT_LOCAL) ||
		(data_id == PM_PEER_DATA_ID_GATT_REMOTE) ||
		(data_id == PM_PEER_DATA_ID_PEER_RANK) ||
		(data_id == PM_PEER_DATA_ID_CENTRAL_ADDR_RES) ||
		(data_id == PM_PEER_DATA_ID_APPLICATION));
}

/**
 * @brief Function for sending a PM_EVT_ERROR_UNEXPECTED event.
 *
 * @param[in]  peer_id    The peer the event pertains to.
 * @param[in]  err_code   The unexpected error that occurred.
 */
static void send_unexpected_error(pm_peer_id_t peer_id, uint32_t err_code)
{
	pm_evt_t error_evt = {.evt_id = PM_EVT_ERROR_UNEXPECTED,
			      .peer_id = peer_id,
			      .params = {.error_unexpected = {
						 .error = err_code,
					 }}};
	pds_evt_send(&error_evt);
}

/* Finds the first occurrence of any peer data for a peer, otherwise returns an error. */
static uint32_t bm_zms_find_peer_data(struct bm_zms_fs *fs, pm_peer_id_t peer_id)
{
	return NRF_ERROR_NOT_FOUND;
}

/* Function for deleting all data belonging to a peer.
 * These operations will be sent to FDS one at a time.
 */
static void peer_data_delete_process(void)
{
	uint32_t ret;
	pm_peer_id_t peer_id;
	uint16_t file_id;

	m_peer_delete_deferred = false;

	peer_id = peer_id_get_next_deleted(PM_PEER_ID_INVALID);

	while ((peer_id != PM_PEER_ID_INVALID) &&
	       (bm_zms_find_peer_data(&fs, peer_id) == NRF_ERROR_NOT_FOUND)) {
		peer_id_free(peer_id);
		peer_id = peer_id_get_next_deleted(peer_id);
	}

#if 0
	if (peer_id != PM_PEER_ID_INVALID) {
		file_id = peer_id_to_file_id(peer_id);
		ret = fds_file_delete(file_id);

		if (ret == FDS_ERR_NO_SPACE_IN_QUEUES) {
			m_peer_delete_deferred = true;
		} else if (ret != NRF_SUCCESS) {
			LOG_ERR("Could not delete peer data. fds_file_delete() returned 0x%x "
				"for peer_id: %d",
				ret, peer_id);
			send_unexpected_error(peer_id, ret);
		}
	}
#endif
}

static void peer_ids_load(void)
{
#if 0
	fds_record_desc_t record_desc;
	fds_flash_record_t record;
	fds_find_token_t ftok;

	memset(&ftok, 0x00, sizeof(fds_find_token_t));

	uint16_t const record_key = peer_data_id_to_record_key(PM_PEER_DATA_ID_BONDING);

	while (fds_record_find_by_key(record_key, &record_desc, &ftok) == NRF_SUCCESS) {
		pm_peer_id_t peer_id;

		/* It is safe to ignore the return value since the descriptor was
		 * just obtained and also 'record' is different from NULL.
		 */
		(void)fds_record_open(&record_desc, &record);
		peer_id = file_id_to_peer_id(record.p_header->file_id);
		(void)fds_record_close(&record_desc);

		(void)peer_id_allocate(peer_id);
	}
#endif
}

static void bm_zms_evt_handler(bm_zms_evt_t const *p_evt)
{
#if 0
	pm_evt_t pds_evt = {.peer_id = file_id_to_peer_id(p_fds_evt->write.file_id)};

	switch (p_fds_evt->id) {
	case FDS_EVT_WRITE:
	case FDS_EVT_UPDATE:
	case FDS_EVT_DEL_RECORD:
		if (file_id_within_pm_range(p_fds_evt->write.file_id) ||
		    record_key_within_pm_range(p_fds_evt->write.record_key)) {
			pds_evt.params.peer_data_update_succeeded.data_id =
				record_key_to_peer_data_id(p_fds_evt->write.record_key);
			pds_evt.params.peer_data_update_succeeded.action =
				(p_fds_evt->id == FDS_EVT_DEL_RECORD) ? PM_PEER_DATA_OP_DELETE
								      : PM_PEER_DATA_OP_UPDATE;
			pds_evt.params.peer_data_update_succeeded.token =
				p_fds_evt->write.record_id;

			if (p_fds_evt->result == NRF_SUCCESS) {
				pds_evt.evt_id = PM_EVT_PEER_DATA_UPDATE_SUCCEEDED;
				pds_evt.params.peer_data_update_succeeded.flash_changed = true;
			} else {
				pds_evt.evt_id = PM_EVT_PEER_DATA_UPDATE_FAILED;
				pds_evt.params.peer_data_update_failed.error = p_fds_evt->result;
			}

			pds_evt_send(&pds_evt);
		}
		break;

	case FDS_EVT_DEL_FILE:
		if (file_id_within_pm_range(p_fds_evt->del.file_id) &&
		    (p_fds_evt->del.record_key == FDS_RECORD_KEY_DIRTY)) {
			if (p_fds_evt->result == NRF_SUCCESS) {
				pds_evt.evt_id = PM_EVT_PEER_DELETE_SUCCEEDED;
				peer_id_free(pds_evt.peer_id);
			} else {
				pds_evt.evt_id = PM_EVT_PEER_DELETE_FAILED;
				pds_evt.params.peer_delete_failed.error = p_fds_evt->result;
			}

			/* Trigger remaining deletes. */
			m_peer_delete_deferred = true;

			pds_evt_send(&pds_evt);
		}
		break;
	default:
		/* No action. */
		break;
	}

	if (m_peer_delete_deferred) {
		peer_data_delete_process();
	}
#endif
}

void pds_peer_data_iterate_prepare(void)
{}

bool pds_peer_data_iterate(pm_peer_data_id_t data_id, pm_peer_id_t *const p_peer_id,
			   pm_peer_data_flash_t *const p_data)
{}

uint32_t pds_init(void)
{
	int err;

	/* Check for re-initialization if debugging. */
	NRF_PM_DEBUG_CHECK(!m_module_initialized);

	err = bm_zms_register(&fs, bm_zms_evt_handler);
	if (err) {
		LOG_ERR("Could not initialize NVM storage. bm_zms_register() returned %d.", err);
		return NRF_ERROR_INTERNAL;
	}

	err = bm_zms_mount(&fs);
	if (err) {
		LOG_ERR("Could not initialize NVM storage. bm_zms_mount() returned %d.", err);
		return NRF_ERROR_RESOURCES;
	}

	peer_id_init();
	peer_ids_load();

	m_module_initialized = true;

	return NRF_SUCCESS;
}

uint32_t pds_peer_data_read(pm_peer_id_t peer_id, pm_peer_data_id_t data_id,
			      pm_peer_data_t *const p_data, uint32_t const *const p_buf_len)
{
	int ret;

	NRF_PM_DEBUG_CHECK(m_module_initialized);
	NRF_PM_DEBUG_CHECK(p_data != NULL);

	VERIFY_PEER_ID_IN_RANGE(peer_id);
	VERIFY_PEER_DATA_ID_IN_RANGE(data_id);

	uint32_t entry_id = peer_id_peer_data_id_to_entry_id(peer_id, data_id);

	ret = bm_zms_read(&fs, entry_id, p_data->p_all_data, *p_buf_len);
	if (ret < 0) {
		LOG_ERR("Could not read data from NVM. bm_zms_read() returned %d. "
			"peer_id: %d",
			ret, peer_id);
		return NRF_ERROR_INTERNAL;
	}

	return NRF_SUCCESS;
}

uint32_t pds_peer_data_store(pm_peer_id_t peer_id, pm_peer_data_const_t const *p_peer_data,
			       pm_store_token_t *p_store_token)
{
	int err;

	NRF_PM_DEBUG_CHECK(m_module_initialized);
	NRF_PM_DEBUG_CHECK(p_peer_data != NULL);

	VERIFY_PEER_ID_IN_RANGE(peer_id);
	VERIFY_PEER_DATA_ID_IN_RANGE(p_peer_data->data_id);

	uint32_t entry_id = peer_id_peer_data_id_to_entry_id(peer_id, p_peer_data->data_id);

        err = bm_zms_write(&fs, entry_id, p_peer_data->p_all_data,
			   p_peer_data->length_words * BYTES_PER_WORD);
	if (err) {
		LOG_ERR("Could not write data to NVM. bm_zms_write() returned %d. "
			"peer_id: %d",
			err, peer_id);
		return NRF_ERROR_INTERNAL;
	}
}

uint32_t pds_peer_data_delete(pm_peer_id_t peer_id, pm_peer_data_id_t data_id)
{
	int err;

	NRF_PM_DEBUG_CHECK(m_module_initialized);

	VERIFY_PEER_ID_IN_RANGE(peer_id);
	VERIFY_PEER_DATA_ID_IN_RANGE(data_id);

	uint32_t entry_id = peer_id_peer_data_id_to_entry_id(peer_id, data_id);

	err = bm_zms_delete(&fs, entry_id);
	if (err) {
		LOG_ERR("Could not delete peer data. bm_zms_delete() returned %d. peer_id: %d, "
			"data_id: %d.",
			err, peer_id, data_id);
		return NRF_ERROR_INTERNAL;
	}
}

pm_peer_id_t pds_peer_id_allocate(void)
{
	NRF_PM_DEBUG_CHECK(m_module_initialized);
	return peer_id_allocate(PM_PEER_ID_INVALID);
}

uint32_t pds_peer_id_free(pm_peer_id_t peer_id)
{
	NRF_PM_DEBUG_CHECK(m_module_initialized);
	VERIFY_PEER_ID_IN_RANGE(peer_id);

	(void)peer_id_delete(peer_id);
	peer_data_delete_process();

	return NRF_SUCCESS;
}

bool pds_peer_id_is_allocated(pm_peer_id_t peer_id)
{
	NRF_PM_DEBUG_CHECK(m_module_initialized);
	return peer_id_is_allocated(peer_id);
}

bool pds_peer_id_is_deleted(pm_peer_id_t peer_id)
{
	NRF_PM_DEBUG_CHECK(m_module_initialized);
	return peer_id_is_deleted(peer_id);
}

pm_peer_id_t pds_next_peer_id_get(pm_peer_id_t prev_peer_id)
{
	NRF_PM_DEBUG_CHECK(m_module_initialized);
	return peer_id_get_next_used(prev_peer_id);
}

pm_peer_id_t pds_next_deleted_peer_id_get(pm_peer_id_t prev_peer_id)
{
	NRF_PM_DEBUG_CHECK(m_module_initialized);
	return peer_id_get_next_deleted(prev_peer_id);
}

uint32_t pds_peer_count_get(void)
{
	NRF_PM_DEBUG_CHECK(m_module_initialized);
	return peer_id_n_ids();
}
